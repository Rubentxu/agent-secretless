//! `asv-vault-tool`: a minimal vault exerciser for the adversarial harness.
//!
//! # Why this binary exists separately from `asv`
//!
//! `docs/14-UAT-ADVERSARIAL.md` describes attacks that need a program that
//! *holds* a secret for a moment: write a canary into a locked vault, then
//! try to read it back out. The production CLI never does that on purpose, so
//! the harness has nothing to attack. This tool performs the exact operations
//! M1 introduced, and nothing else, so that a leak in the vault layer shows up
//! as a filesystem or process-level finding rather than as a unit-test failure
//! nobody outside the crate can observe.
//!
//! # What it must never do
//!
//! It must never print a secret. Every subcommand writes metadata and
//! length-only diagnostics to stdout. If a future change made this tool print
//! a canary, the harness would flag it, and the CLI would too, because both
//! scan the same output.

use std::io::Write;
use std::path::PathBuf;

use asv_domain::secret::SecretBytes;
use asv_vault::store::{CredentialKind, CredentialMetadata};
use asv_vault::{KdfParams, VaultStore};
use clap::{Parser, Subcommand};
use secrecy::SecretString;

/// The canary the harness plants and then hunts for.
///
/// It matches the pattern used across the ASV test suite so that a single
/// grep in the harness finds every occurrence.
const CANARY: &str = "ASV-CANARY-4f2b9c1e7a-VAULTTOOL";

#[derive(Parser)]
#[command(
    name = "asv-vault-tool",
    about = "Exercises the ASV vault for the adversarial harness. Never prints a secret."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a vault containing a canary secret.
    Create {
        /// Vault path.
        #[arg(long)]
        vault: PathBuf,
        /// Passphrase. Never taken from the environment or argv by the harness.
        #[arg(long)]
        passphrase: String,
        /// Use fast KDF parameters, for harness runtime only.
        #[arg(long, default_value_t = false)]
        fast: bool,
    },
    /// List credential metadata. Never reveals a secret.
    List {
        /// Vault path.
        #[arg(long)]
        vault: PathBuf,
        /// Passphrase.
        #[arg(long)]
        passphrase: String,
    },
    /// Read one secret's length without revealing it.
    ///
    /// The length is metadata, not material: a connector needs to know how
    /// many bytes it is signing. Printing the bytes would be a retrieval path.
    Probe {
        /// Vault path.
        #[arg(long)]
        vault: PathBuf,
        /// Passphrase.
        #[arg(long)]
        passphrase: String,
        /// Credential id.
        #[arg(long)]
        id: String,
    },
    /// Write an encrypted backup.
    Backup {
        /// Vault path.
        #[arg(long)]
        vault: PathBuf,
        /// Backup destination.
        #[arg(long)]
        out: PathBuf,
        /// Vault passphrase.
        #[arg(long)]
        passphrase: String,
        /// Recovery factor for the backup.
        #[arg(long)]
        recovery: String,
    },
    /// Restore a backup onto a clean path.
    Restore {
        /// Backup path.
        #[arg(long)]
        backup: PathBuf,
        /// Destination vault path.
        #[arg(long)]
        out: PathBuf,
        /// Recovery factor.
        #[arg(long)]
        recovery: String,
    },
    /// Report runtime secret-memory support.
    Memfd,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match cli.command {
        Command::Create {
            vault,
            passphrase,
            fast,
        } => {
            let params = if fast {
                KdfParams::fast_for_tests()
            } else {
                KdfParams::default()
            };
            // The passphrase is needed twice: once to create the vault and
            // once to derive the key that writes into it. `SecretString` is
            // not `Clone`, so wrap the same source value twice rather than
            // duplicating the secret.
            let mut store =
                VaultStore::create(&vault, &SecretString::from(passphrase.clone()), params)?;
            let key = store
                .header()
                .unlock(&SecretString::from(passphrase.clone()))
                .expect("unlock a vault we just created");
            store.insert(
                &key,
                CredentialMetadata::new(
                    "canary",
                    "harness canary",
                    CredentialKind::Opaque,
                    "harness",
                    "harness",
                    0,
                ),
                SecretBytes::new(CANARY.as_bytes().to_vec()),
            )?;
            writeln!(out, "created revision={} credentials=1", store.revision())?;
        }
        Command::List { vault, passphrase } => {
            let store = VaultStore::open(&vault, &SecretString::from(passphrase))?;
            for meta in store.list() {
                writeln!(
                    out,
                    "id={} label={} kind={} provider={} exportability={:?}",
                    meta.id, meta.label, meta.kind, meta.provider, meta.exportability
                )?;
            }
            writeln!(out, "count={}", store.list().len())?;
        }
        Command::Probe {
            vault,
            passphrase,
            id,
        } => {
            let store = VaultStore::open(&vault, &SecretString::from(passphrase.clone()))?;
            let key = store
                .header()
                .unlock(&SecretString::from(passphrase))
                .expect("unlock");
            // Length only. The bytes stay inside the closure.
            let len = store.with_secret(&key, &id, |bytes| bytes.len())?;
            writeln!(out, "id={id} len={len}")?;
        }
        Command::Backup {
            vault,
            out: destination,
            passphrase,
            recovery,
        } => {
            let store = VaultStore::open(&vault, &SecretString::from(passphrase))?;
            store.backup(&destination, &SecretString::from(recovery))?;
            writeln!(out, "backup written")?;
        }
        Command::Restore {
            backup,
            out: destination,
            recovery,
        } => {
            let store = VaultStore::restore(&backup, &destination, &SecretString::from(recovery))?;
            writeln!(
                out,
                "restored revision={} credentials={}",
                store.revision(),
                store.list().len()
            )?;
        }
        Command::Memfd => {
            let support = asv_vault::memfd::probe();
            writeln!(
                out,
                "available={} sealing={}",
                support.available, support.allow_sealing
            )?;
            writeln!(out, "strategy={}", support.fallback_strategy().join(","))?;
        }
    }
    Ok(())
}
