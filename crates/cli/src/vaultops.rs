//! The one vault operation `asv` performs: creating an empty one.
//!
//! # Why the CLI links the vault at all
//!
//! `distribution/manifest.toml` classifies `asv-vault-tool` as
//! `test-harness` with `forbidden_in_production = true`, and UAT-DX-001
//! asserts it is absent from the bundle. The obvious way to create a vault
//! during installation was therefore to shell out to that tool — which is
//! also what `scripts/install-broker-service.sh` used to tell users to type,
//! in three steps that could not work, because the binary it named is not
//! shipped to anyone.
//!
//! So `asv setup` links `asv-vault` and calls the store directly. That is a
//! real dependency and it is worth being clear about what it does and does
//! not grant: `VaultStore` exposes create, open and persist, and no operation
//! that hands a stored secret back to a caller. The CLI gains the ability to
//! make a key, not the ability to read one, which is the property
//! `no_subcommand_exposes_a_secret` asserts over the whole command surface.

use std::path::Path;

use secrecy::SecretString;

/// The KDF shape `asv setup` uses.
///
/// A type rather than a bare `KdfParams` so that the choice of parameters is
/// a value somebody wrote down, not a value somebody forgot. `production` is
/// the only constructor a real run uses, and
/// `setup_production_kdf_is_the_strong_shape` in `setup::tests` is what stops
/// the two from being quietly equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// 64 MiB, 3 passes, 4 lanes. What an operator's vault gets.
    Production,
    /// 8 MiB, 1 pass, 1 lane. What the tests get, and the crate's own
    /// "never used for a real vault" parameters.
    FastForTests,
}

impl Kdf {
    pub fn params(self) -> asv_vault::KdfParams {
        match self {
            Kdf::Production => asv_vault::KdfParams::default(),
            Kdf::FastForTests => asv_vault::KdfParams::fast_for_tests(),
        }
    }
}

/// Creates an empty vault, unlocked.
///
/// The two parameter sets are not interchangeable: a vault created with the
/// test parameters opens instantly, and a vault that opens instantly is one
/// whose contents can be enumerated by anybody who can copy the file. So the
/// choice is a named variant, `setup` always passes `Kdf::Production`, and
/// there is no command-line flag that can select the other one — a flag would
/// eventually be set by something, and it would be set by a script.
pub fn create_empty_vault(path: &Path, passphrase: &str, kdf: Kdf) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let secret = SecretString::from(passphrase.to_string());
    asv_vault::VaultStore::create(path, &secret, kdf.params())
        .map(|_| ())
        .map_err(to_io)
}

fn to_io(error: asv_vault::VaultError) -> std::io::Error {
    // The vault error carries no secret — it names paths and envelope
    // parameters — so formatting it into the CLI's own error channel is safe.
    // The one place that would not be safe is a failure after a secret is
    // already inside the operation, and `VaultError` has no variant that
    // carries payload bytes.
    std::io::Error::other(error.to_string())
}
