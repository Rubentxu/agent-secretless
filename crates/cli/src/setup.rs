//! `asv setup` — bring an installation to a working state, twice.
//!
//! # What `setup` is allowed to create and what it is not
//!
//! `setup` creates: the runtime directories, a vault, a passphrase, a systemd
//! user unit. All four are either empty or regenerable from nothing.
//!
//! `setup` never overwrites: an existing vault, an existing passphrase.
//! UAT-DX-003 asks that running it twice leave the same observable state and
//! not regenerate or destroy secrets, and the way to guarantee that is not to
//! be careful on the second run — it is to have no code path that can rewrite
//! either file when it already exists. The passphrase is the only thing
//! standing between the vault file on disk and the credentials in it, so a
//! `setup` that "refreshes" it is a `setup` that can end a credential store,
//! and there is deliberately no flag that asks it to.
//!
//! # The partial states
//!
//! Two files that must agree can be found disagreeing, and each disagreement
//! is a different problem with a different answer:
//!
//! | vault | passphrase | what `setup` does |
//! |---|---|---|
//! | absent | absent | creates both |
//! | present | present | touches nothing; verifies the passphrase opens the vault |
//! | present | absent | **refuses.** The vault is there and its key is not recoverable |
//! | absent | present | creates the vault with the existing passphrase, and warns |
//!
//! The third row is the one that decides the design. The tempting action —
//! "the passphrase is gone, mint a new one and an empty vault" — destroys
//! every credential in the file. `setup` prints what it found and what the
//! options are, and exits `blocked`.
//!
//! The fourth row is not destructive, because there is nothing to destroy:
//! the vault is gone. It still warns, because the most likely cause is a
//! moved or unmounted data directory, and creating a fresh empty vault at the
//! configured path would make that look like a successful setup.

use crate::layout::{self, BrokerLookup, Layout};

use std::io::{Read, Write};
use std::path::Path;

/// The unit, embedded so that `setup` does not depend on a source checkout.
///
/// `unit_matches_the_repository` is what keeps the embed honest: the file in
/// the repository is the file that installs, and an install that silently
/// carried a different unit than the one under review would make
/// `systemctl --user cat` and the source impossible to diff.
const UNIT: &str = include_str!("../../../packaging/asv-brokerd.service");

/// Bytes of entropy in a generated passphrase, rendered as hex.
const PASSPHRASE_BYTES: usize = 32;

/// What one `setup` run did.
///
/// Every field is a fact about the filesystem after the run, not an
/// intention, because UAT-DX-003 is about the state a second run observes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupOutcome {
    pub created_dirs: Vec<String>,
    pub created_vault: bool,
    pub created_passphrase: bool,
    pub installed_unit: bool,
    pub vault_verified: bool,
    pub service_started: bool,
    /// Human-readable lines, in the order they should be printed. Kept as
    /// data so `--json` and the human rendering say the same things.
    pub notes: Vec<String>,
    /// Stable, machine-readable warning codes.
    pub warning_codes: Vec<String>,
    /// Set when the run stopped short of a working installation.
    pub blocked: Option<Blocked>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub code: String,
    pub message: String,
    pub remedy: String,
}

impl SetupOutcome {
    fn note(&mut self, line: impl Into<String>) {
        self.notes.push(line.into());
    }

    /// Whether the run stopped short. Named apart from the field on purpose:
    /// a method called `blocked` next to a field called `blocked` resolves to
    /// the field at every call site, and the resulting compile error is about
    /// `Option` implementing `Not`.
    pub fn is_blocked(&self) -> bool {
        self.blocked.is_some()
    }
}

/// Runs setup against `layout`. Performs real filesystem work, with the
/// production KDF parameters.
///
/// [`run_with`] is what the tests call. The difference is the cost of one
/// Argon2id derivation — about a second, and multiplied by a dozen tests into
/// minutes of wall clock for a suite nobody will re-run. It is not a
/// difference in behaviour: everything else, including the permissions, the
/// idempotence table and the unit, is identical, and one test runs the real
/// path to keep the two from drifting.
pub fn run(layout: &Layout) -> std::io::Result<SetupOutcome> {
    run_with(layout, crate::vaultops::Kdf::Production)
}

/// The same, with the vault KDF chosen by the caller.
pub fn run_with(layout: &Layout, kdf: crate::vaultops::Kdf) -> std::io::Result<SetupOutcome> {
    let mut outcome = SetupOutcome {
        created_dirs: Vec::new(),
        created_vault: false,
        created_passphrase: false,
        installed_unit: false,
        vault_verified: false,
        service_started: false,
        notes: Vec::new(),
        warning_codes: Vec::new(),
        blocked: None,
    };

    // 1. The private broker. Everything below writes a unit that runs this
    //    file, so there is no point creating directories for an installation
    //    that cannot start.
    match &layout.broker_lookup {
        BrokerLookup::Found(p) => {
            outcome.note(format!("private broker: {}", p.display()));
        }
        BrokerLookup::Refused { path, reason } => {
            outcome.blocked = Some(Blocked {
                code: "BROKER_BINARY_MISSING".into(),
                message: reason.explain(path),
                remedy: "install the agent-secretless bundle, which places asv-brokerd \
                         outside PATH, then run `asv setup` again"
                    .into(),
            });
            return Ok(outcome);
        }
    }

    // 2. Directories. 0700 on both: the broker refuses to open its vault
    //    anywhere another user can reach, and creating them 0755 and relying
    //    on the operator to notice is not a defence.
    for dir in [&layout.config_dir, &layout.data_dir] {
        if !dir.exists() {
            create_private_dir(dir)?;
            outcome.created_dirs.push(dir.display().to_string());
        } else if let Some(mode) = layout::mode_of(dir) {
            if mode & 0o077 != 0 {
                set_mode(dir, 0o700)?;
                outcome.note(format!(
                    "tightened {} from {mode:04o} to 0700",
                    dir.display()
                ));
            }
        }
    }
    // The socket's parent. `resolve_socket_path` already ends in `asv`, so
    // this is the directory and NOT the one above it — an earlier version
    // appended `asv` a second time and produced `~/run/asv/asv`, a directory
    // the broker never binds into and the operator never asked for.
    let runtime_dir = socket_dir();
    if !runtime_dir.exists() {
        create_private_dir(&runtime_dir)?;
        outcome.created_dirs.push(runtime_dir.display().to_string());
    }

    // 3. Vault and passphrase — the idempotence table, in the module docs.
    let vault_exists = layout.vault.exists();
    let passphrase_exists = layout.passphrase.exists();

    match (vault_exists, passphrase_exists) {
        (false, false) => {
            let passphrase = generate_passphrase()?;
            write_secret(&layout.passphrase, passphrase.as_bytes())?;
            outcome.created_passphrase = true;
            crate::vaultops::create_empty_vault(&layout.vault, passphrase.as_str(), kdf)?;
            outcome.created_vault = true;
            outcome.note(format!("created vault {}", layout.vault.display()));
            outcome.note(format!(
                "wrote a generated passphrase to {} (mode 0600)",
                layout.passphrase.display()
            ));
            outcome.note(
                "the passphrase is the only key to this vault. Back it up somewhere \
                 other than this machine before storing anything in it.",
            );
        }
        (true, true) => {
            // The idempotent case. Read the passphrase and prove it opens the
            // vault, so a second run reports a *verified* installation rather
            // than a silently unchanged one.
            match verify_vault(layout) {
                Verify::Opens => {
                    outcome.vault_verified = true;
                    outcome.note("vault and passphrase already present; left untouched");
                }
                Verify::WrongPassphrase => {
                    outcome.blocked = Some(Blocked {
                        code: "PASSPHRASE_MISMATCH".into(),
                        message: format!(
                            "the passphrase at {} does not open the vault at {}",
                            layout.passphrase.display(),
                            layout.vault.display()
                        ),
                        remedy: "restore the correct passphrase, or restore a backup of \
                                 the vault. `asv setup` will not overwrite either, and \
                                 the credentials in that vault are not recoverable \
                                 without the key."
                            .into(),
                    });
                    return Ok(outcome);
                }
                Verify::Unreadable(reason) => {
                    outcome.blocked = Some(Blocked {
                        code: "VAULT_UNREADABLE".into(),
                        message: reason,
                        remedy: "check the file permissions on the vault and the passphrase".into(),
                    });
                    return Ok(outcome);
                }
            }
        }
        (true, false) => {
            outcome.blocked = Some(Blocked {
                code: "PASSPHRASE_MISSING".into(),
                message: format!(
                    "a vault exists at {} but there is no passphrase at {}",
                    layout.vault.display(),
                    layout.passphrase.display()
                ),
                remedy: "restore the passphrase from your backup. A new one will not \
                         open this vault, and creating a new vault here would replace a \
                         file that holds credentials."
                    .into(),
            });
            return Ok(outcome);
        }
        (false, true) => {
            // Not destructive — there is no vault to destroy — but almost
            // always a symptom, so it is said out loud.
            outcome.warning_codes.push("VAULT_MISSING_RECOVERED".into());
            let passphrase = std::fs::read_to_string(&layout.passphrase).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("cannot read {}: {e}", layout.passphrase.display()),
                )
            })?;
            let passphrase = passphrase.trim_end_matches(['\n', '\r']).to_string();
            crate::vaultops::create_empty_vault(&layout.vault, &passphrase, kdf)?;
            outcome.created_vault = true;
            outcome.note(format!(
                "the passphrase at {} existed but the vault did not; created an empty vault",
                layout.passphrase.display()
            ));
            outcome.note(
                "if you moved or unmounted the data directory, stop here: this vault \
                 does not contain the credentials you had before.",
            );
        }
    }

    // 4. The unit. Written from the embedded template, with `ExecStart`
    //    rewritten to the paths this installation actually resolved.
    //
    //    R8 in `11-RISKS-OPEN-QUESTIONS.md`: "asv setup reescribe/verifica el
    //    ExecStart de su propia instalación; doctor compara paths y
    //    versiones." The template spells the paths as `%h` and `%t`, which are
    //    correct for a default layout and wrong for every other one — a mise
    //    install, or a user with `XDG_DATA_HOME` pointed elsewhere. A unit
    //    left with the template's paths after such an upgrade starts a broker
    //    from the *previous* installation, holding the previous vault.
    //
    //    So the line is composed here, from the same `Layout` everything else
    //    used, and `doctor` compares what is on disk against what it resolves.
    let unit = render_unit(UNIT, layout, layout.broker_lookup.path());
    if let Some(parent) = layout.unit.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let unit_changed = std::fs::read_to_string(&layout.unit)
        .map(|existing| existing != unit)
        .unwrap_or(true);
    if unit_changed {
        std::fs::write(&layout.unit, &unit)?;
        set_mode(&layout.unit, 0o644)?;
        outcome.installed_unit = true;
        outcome.note(format!("installed {}", layout.unit.display()));
    } else {
        outcome.note(format!("{} already current", layout.unit.display()));
    }

    // 5. The service. `setup` starts it when systemd is there and says so
    //    plainly when it is not, rather than exiting zero over a broker that
    //    was never asked to run.
    match service_control(&["enable", "--now"]) {
        Ok(()) => {
            outcome.service_started = true;
            outcome.note("enabled and started asv-brokerd.service");
        }
        Err(NoSystemd::NoUserManager) => {
            outcome.warning_codes.push("NO_SYSTEMD_USER_SESSION".into());
            outcome.note(
                "no systemd user session here, so the service was not started. \
                 The rest of the installation is in place; start it from a login \
                 session with: systemctl --user enable --now asv-brokerd",
            );
        }
        Err(NoSystemd::NotLinux) => {
            outcome.warning_codes.push("NO_SYSTEMD".into());
            outcome.note("not Linux, so no service was installed. Start the broker by hand.");
        }
    }

    Ok(outcome)
}

/// Composes the unit this installation runs, from the embedded template.
///
/// Only the `ExecStart` line is replaced. Everything else — the hardening
/// directives, the lifecycle, the comment explaining why the sandbox is
/// absent — is carried through byte for byte, because that prose is the
/// record of a decision and editing it here would edit it in two places.
///
/// The paths are absolute and come from `Layout`. Absolute because the
/// template's `%h` and `%t` are systemd's guesses about where things are, and
/// a broker that starts against the wrong vault is worse than one that does
/// not start.
pub fn render_unit(template: &str, layout: &Layout, broker: &std::path::Path) -> String {
    let socket = asv_ipc_protocol::socket::resolve_socket_path(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        unsafe { libc::getuid() },
    );
    let exec_start = format!(
        "ExecStart={} {} --vault {} --passphrase-file {}",
        broker.display(),
        socket.display(),
        layout.vault.display(),
        layout.passphrase.display(),
    );

    let mut out = String::with_capacity(template.len() + exec_start.len());
    for line in template.lines() {
        if line.starts_with("ExecStart=") {
            out.push_str(&exec_start);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

enum Verify {
    Opens,
    WrongPassphrase,
    Unreadable(String),
}

fn verify_vault(layout: &Layout) -> Verify {
    let Ok(bytes) = std::fs::read(&layout.passphrase) else {
        return Verify::Unreadable(format!("cannot read {}", layout.passphrase.display()));
    };
    let text = String::from_utf8_lossy(&bytes);
    let secret = secrecy::SecretString::from(text.trim_end_matches(['\n', '\r']).to_string());
    match asv_vault::VaultStore::open(&layout.vault, &secret) {
        Ok(_) => Verify::Opens,
        Err(_) => Verify::WrongPassphrase,
    }
}

enum NoSystemd {
    NotLinux,
    NoUserManager,
}

/// Talks to the user manager. A failure to reach it is not an error: there is
/// a real class of machine — a container, a CI runner, an SSH session with no
/// login — where there is no user manager and the installation is still
/// correct.
///
/// The timeout is load-bearing, and it was found by a test that hung for
/// seven minutes. `systemctl --user` on a machine with no session bus does
/// not fail; it waits for a D-Bus reply that will never come. So `asv setup`
/// — the command a new user runs first, on whatever machine they happen to be
/// on — could block indefinitely in exactly the environment where it is most
/// needed and least expected to. `NO_SYSTEMD_USER_SESSION` after a few seconds
/// is the truthful answer, and it is what the rest of the code already
/// expected to receive.
fn service_control(args: &[&str]) -> Result<(), NoSystemd> {
    if !cfg!(target_os = "linux") {
        return Err(NoSystemd::NotLinux);
    }
    // The test seam. `run()` reaching the host's real user manager is a
    // property no unit test wants: it would start a service on the machine
    // running the suite, and on a developer laptop it would enable a unit
    // under their own session. The name says what it suppresses so that a
    // reader does not have to trace the call to find out.
    if std::env::var_os(NO_SERVICE_ENV).is_some() {
        return Err(NoSystemd::NoUserManager);
    }
    // `--no-block` on our side is not available — `systemctl` has no
    // "give up" flag — so the wait is bounded by us instead.
    let child = std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .arg("asv-brokerd.service")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(child) => child,
        // No `systemctl` at all.
        Err(_) => return Err(NoSystemd::NoUserManager),
    };

    let deadline = std::time::Instant::now() + SERVICE_CONTROL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(NoSystemd::NoUserManager),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    // Killed rather than left running: a `systemctl` still
                    // blocked on a bus that will never answer would outlive
                    // the command that spawned it.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(NoSystemd::NoUserManager);
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return Err(NoSystemd::NoUserManager),
        }
    }
}

/// How long to wait for the user manager before deciding there isn't one.
const SERVICE_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Set to any value to stop `setup` from touching the user manager. Tests
/// only. `setup` itself never sets it, and a user who sets it gets the
/// "no systemd user session" path, which tells them to start the broker by
/// hand — the safe direction to be wrong in.
pub const NO_SERVICE_ENV: &str = "ASV_SETUP_NO_SERVICE";

/// 32 bytes of kernel entropy, hex-encoded.
///
/// Read from `/dev/urandom` directly rather than through a `rand` handle so
/// that the source is visible at the call site: this value is the key to a
/// credential store, and "where did the randomness come from" should be
/// answerable by reading one line.
fn generate_passphrase() -> std::io::Result<String> {
    let mut bytes = [0u8; PASSPHRASE_BYTES];
    let mut file = std::fs::File::open("/dev/urandom")?;
    file.read_exact(&mut bytes)?;

    let mut out = String::with_capacity(PASSPHRASE_BYTES * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Writes a secret with `0600`, refusing to widen an existing file's mode.
///
/// `OpenOptions::mode` only applies when the file is created, so a
/// pre-existing world-readable passphrase would keep its mode without this
/// explicit set. The pass loop is safe here: this is not a privileged process
/// and there is no adversary racing it for the file; the case being closed is
/// the ordinary one of a file that was already there.
fn write_secret(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;

    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_mode(path, 0o700)
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
}

/// The directory the broker binds its socket into, derived by the same rule
/// the broker itself uses. Asking the protocol crate for it is what keeps the
/// two from disagreeing on a machine where `XDG_RUNTIME_DIR` is not the
/// spec default.
fn socket_dir() -> std::path::PathBuf {
    asv_ipc_protocol::socket::resolve_socket_path(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        unsafe { libc::getuid() },
    )
    .parent()
    .map(|p| p.to_path_buf())
    .unwrap_or_else(std::env::temp_dir)
}

#[cfg(test)]
mod tests;
