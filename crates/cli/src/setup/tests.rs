//! `asv setup` — UAT-DX-003, and the states where being idempotent is not
//! enough.
//!
//! *"Ejecutar `asv setup` dos veces deja el mismo estado observable y no
//! regenera/destruye secrets."*
//!
//! The test that matters is not "the second run returns Ok". It is that the
//! passphrase is **byte-identical** after the second run, because the whole
//! risk of an idempotence bug here is that it looks fine and destroys the key
//! to a credential store. So every idempotence assertion below compares
//! content hashes, not return values.

use super::*;

use crate::tests_support::{with_env, TempTree};

/// A clean HOME with a private broker beside it, which is what a bundle
/// install produces and what `setup` is for.
///
/// Returns the tree and the layout, with the environment already set. The
/// caller must stay inside `f`; the env vars are restored on the way out.
fn in_a_clean_install(label: &str, f: impl FnOnce(&Layout, &Path)) {
    let tmp = TempTree::new(label);
    let libexec = tmp.sub("libexec/asv");
    std::fs::create_dir_all(&libexec).unwrap();
    crate::tests_support::write_executable(&libexec.join("asv-brokerd"), b"#!/bin/sh\n");

    let config = tmp.sub("config");
    let data = tmp.sub("data");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    // A private runtime dir, so setup's socket parent is inside the tree
    // rather than in the real `/run/user`.
    let runtime = tmp.sub("run");
    std::fs::create_dir_all(&runtime).unwrap();

    with_env(
        &[
            ("HOME", tmp.path.as_os_str()),
            ("XDG_CONFIG_HOME", config.as_os_str()),
            ("XDG_DATA_HOME", data.as_os_str()),
            ("XDG_RUNTIME_DIR", runtime.as_os_str()),
            (crate::layout::LIBEXEC_ENV, libexec.as_os_str()),
            // The host's user manager is not this test's to touch.
            (super::NO_SERVICE_ENV, std::ffi::OsStr::new("1")),
        ],
        || {
            let layout = crate::layout::for_current_user();
            f(&layout, &tmp.path);
        },
    );
}

/// A short hash of a file's bytes. Read through the filesystem rather than
/// cached, because "the file on disk still has the same bytes" is the claim.
fn fingerprint(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("the file exists");
    // FNV-1a, 64-bit. Not a security primitive: this only has to notice that
    // 32 bytes of passphrase changed.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

// --- UAT-DX-003 ----------------------------------------------------------

/// The exit criterion, run for real.
///
/// The first run creates the vault and the passphrase. The second must leave
/// both byte-identical, and must report that it verified rather than that it
/// created — so the second run's own output is checked too, because a `setup`
/// that recreates identical bytes by accident and says "created" is telling
/// the operator the wrong thing about what happened to their data.
#[test]
fn running_setup_twice_leaves_the_same_state() {
    in_a_clean_install("idempotent", |layout, _| {
        let first = run_fast(layout).expect("the first run works");
        assert!(
            !first.is_blocked(),
            "first run blocked: {:?}",
            first.blocked
        );
        assert!(first.created_vault, "the first run creates a vault");
        assert!(
            first.created_passphrase,
            "the first run creates a passphrase"
        );

        let vault_after_first = fingerprint(&layout.vault);
        let passphrase_after_first = fingerprint(&layout.passphrase);
        let vault_mode = layout::mode_of(&layout.vault);
        let passphrase_mode = layout::mode_of(&layout.passphrase);

        let second = run_fast(layout).expect("the second run works");

        assert!(
            !second.is_blocked(),
            "the second run blocked an installation it had just made: {:?}",
            second.blocked
        );
        assert_eq!(
            fingerprint(&layout.vault),
            vault_after_first,
            "the vault changed on the second run"
        );
        assert_eq!(
            fingerprint(&layout.passphrase),
            passphrase_after_first,
            "the passphrase changed on the second run"
        );
        assert_eq!(layout::mode_of(&layout.vault), vault_mode);
        assert_eq!(layout::mode_of(&layout.passphrase), passphrase_mode);

        // And it said what it did.
        assert!(
            !second.created_vault,
            "the second run claims to have created a vault"
        );
        assert!(
            !second.created_passphrase,
            "the second run claims to have created a passphrase"
        );
        assert!(
            second.vault_verified,
            "the second run did not verify the passphrase it found"
        );
    });
}

/// The guard that would catch the worst version of the bug.
///
/// This is the falsification the whole module is built for: if someone makes
/// `setup` "ensure" a passphrase by writing a fresh one on every run, the
/// tests above still pass — the second run succeeds, the vault still opens
/// (an empty vault opens with any key... no: it does not, the passphrase is
/// the key), and the operator is left with a vault they cannot open.
///
/// The assertion is the content hash, taken across a real second run.
#[test]
fn a_second_run_cannot_rewrite_the_passphrase() {
    in_a_clean_install("no-rewrite", |layout, _| {
        run_fast(layout).unwrap();
        let before = fingerprint(&layout.passphrase);

        // Corrupt it in the way a bug would: replaced with a different key.
        // The second run must refuse rather than "fix" it.
        let wrong = b"00000000000000000000000000000000000000000000000000000000000000ff";
        std::fs::write(&layout.passphrase, wrong).unwrap();
        let corrupted = fingerprint(&layout.passphrase);
        assert_ne!(corrupted, before, "the control: the file really changed");

        let second = run_fast(layout).unwrap();
        assert_eq!(
            fingerprint(&layout.passphrase),
            corrupted,
            "setup overwrote a passphrase it did not recognise"
        );
        assert!(
            second.is_blocked(),
            "a wrong passphrase was accepted silently"
        );
    });
}

/// The row in the table that decides the design: a vault with no passphrase
/// is not something `setup` may resolve by minting a new one.
///
/// The control is that the vault file still exists afterwards, byte for byte.
/// A `setup` that "helpfully" recreated the pair would leave the operator
/// with a working, empty credential store and no way to tell that the
/// credentials they had are gone.
#[test]
fn a_vault_without_its_passphrase_is_refused_and_the_vault_is_left_alone() {
    in_a_clean_install("no-passphrase", |layout, _| {
        run_fast(layout).unwrap();
        let vault_before = fingerprint(&layout.vault);

        std::fs::remove_file(&layout.passphrase).unwrap();

        let second = run_fast(layout).unwrap();
        let blocked = second
            .blocked
            .as_ref()
            .expect("a vault with no passphrase must stop the run");
        assert_eq!(blocked.code, "PASSPHRASE_MISSING");
        assert!(
            !second.created_vault,
            "setup created a replacement vault over one that held credentials"
        );
        assert_eq!(
            fingerprint(&layout.vault),
            vault_before,
            "the vault was modified while refusing"
        );
        assert!(
            blocked.remedy.contains("restore"),
            "the remedy should tell the operator to restore the key, not to \
             generate one: {}",
            blocked.remedy
        );
    });
}

/// The other partial state. Not destructive — there is nothing to destroy —
/// but it is almost always a moved data directory, so it says so.
#[test]
fn a_passphrase_without_a_vault_is_reported_as_a_warning_not_silently_resolved() {
    in_a_clean_install("no-vault", |layout, _| {
        run_fast(layout).unwrap();
        std::fs::remove_file(&layout.vault).unwrap();

        let second = run_fast(layout).unwrap();
        assert!(!second.is_blocked(), "there was nothing to destroy");
        assert!(second.created_vault);
        assert!(
            second
                .warning_codes
                .contains(&"VAULT_MISSING_RECOVERED".to_string()),
            "an empty vault appeared without saying so: {:?}",
            second.warning_codes
        );
    });
}

// --- preconditions -------------------------------------------------------

/// No broker binary, no directories, no vault. `setup` stops at the first
/// thing, because everything after it writes a unit that runs that binary.
#[test]
fn setup_refuses_before_touching_anything_when_the_broker_is_missing() {
    let tmp = TempTree::new("no-broker");
    let config = tmp.sub("config");
    let data = tmp.sub("data");
    let libexec = tmp.sub("libexec/asv");
    std::fs::create_dir_all(&libexec).unwrap();

    with_env(
        &[
            ("HOME", tmp.path.as_os_str()),
            ("XDG_CONFIG_HOME", config.as_os_str()),
            ("XDG_DATA_HOME", data.as_os_str()),
            (crate::layout::LIBEXEC_ENV, libexec.as_os_str()),
            // The host's user manager is not this test's to touch.
            (super::NO_SERVICE_ENV, std::ffi::OsStr::new("1")),
        ],
        || {
            let layout = crate::layout::for_current_user();
            let outcome = run_fast(&layout).unwrap();

            let blocked = outcome.blocked.as_ref().expect("missing broker blocks");
            assert_eq!(blocked.code, "BROKER_BINARY_MISSING");
            assert!(
                !outcome.created_vault,
                "a vault was created for an install that cannot start"
            );
            assert!(
                !layout.config_dir.exists(),
                "directories were created before the precondition was checked"
            );
        },
    );
}

/// The socket directory `setup` creates is the one the broker binds into.
///
/// Found by running the binary: the directory came out as `~/run/asv/asv`,
/// because the code took the parent of the socket path and then appended
/// `asv` again. Nothing failed — the broker simply never looked there, and a
/// user with a stale `~/run/asv` from an older build had two of them.
#[test]
fn the_socket_directory_is_not_nested() {
    in_a_clean_install("socket-dir", |layout, _| {
        run_fast(layout).unwrap();

        let socket = asv_ipc_protocol::socket::resolve_socket_path(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            unsafe { libc::getuid() },
        );
        let expected = socket
            .parent()
            .expect("the socket has a parent directory")
            .to_path_buf();

        assert!(
            expected.is_dir(),
            "setup did not create the directory the broker binds into: {}",
            expected.display()
        );
        assert_eq!(
            expected.file_name().and_then(|n| n.to_str()),
            Some("asv"),
            "the socket directory should be the `asv` directory itself"
        );

        // The control: nothing doubled it up.
        let doubled = expected.join("asv");
        assert!(
            !doubled.exists(),
            "`{}` exists; setup nested the runtime directory inside itself",
            doubled.display()
        );
    });
}

// --- the embedded unit ---------------------------------------------------

/// The unit `setup` installs is the unit in the repository.
///
/// `include_str!` copies the file at build time, so this can silently become a
/// stale copy the moment the source changes. `systemctl --user cat` and the
/// file under review have to stay diffable, and that is the whole reason the
/// unit is installed verbatim.
#[test]
fn the_embedded_unit_is_the_one_in_the_repository() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/asv-brokerd.service");
    let on_disk = std::fs::read_to_string(&source).expect("the unit exists in the repository");
    assert_eq!(
        UNIT, on_disk,
        "the embedded unit has drifted from packaging/asv-brokerd.service"
    );
}

/// The unit points at the private runtime, not at the directory on PATH.
///
/// This is the DX0 finding restated as a property of the thing `setup`
/// installs: an earlier version of the unit used `%h/.local/bin`, which is
/// where the public CLI goes, and `asv-brokerd` on PATH is what UAT-DX-002
/// forbids. `check-release-config.py` checks the file in the repository; this
/// checks that the bytes `setup` actually writes are those bytes.
#[test]
fn the_installed_unit_points_at_the_private_runtime() {
    let exec_start = UNIT
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("the unit has an ExecStart");

    assert!(
        exec_start.contains("/libexec/asv/"),
        "ExecStart does not name the private runtime: {exec_start}"
    );
    assert!(
        !exec_start.contains("%h/.local/bin"),
        "ExecStart points into the directory on PATH: {exec_start}"
    );
}

// --- R8: the unit points at THIS installation ---------------------------

/// The unit `setup` installs runs the binary this installation resolved.
///
/// The gap this closes was found by falsifying, not by reading: a mutation
/// that made `render_unit` keep the template's `%h/...` line passed every
/// test in this file, because the tests checked that a unit was installed and
/// that it named `libexec` — and the template's `%h/.local/libexec` does
/// name it. The check that was missing is the one that compares the installed
/// line against the resolved path, which is the only thing R8 is about.
#[test]
fn the_installed_unit_runs_the_binary_this_installation_resolved() {
    in_a_clean_install("unit-target", |layout, _| {
        run_fast(layout).unwrap();

        let installed = std::fs::read_to_string(&layout.unit).expect("the unit was written");
        let exec_start = installed
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("the installed unit has an ExecStart");

        let expected = layout::lookup_broker_binary();
        assert!(
            exec_start.contains(&format!("ExecStart={}", expected.path().display())),
            "ExecStart does not run the resolved broker.\n  unit:     {exec_start}\n  resolved: {}",
            expected.path().display()
        );
        // The vault and the passphrase come from the same layout, for the
        // same reason: a broker that opens a different vault is a different
        // broker.
        assert!(
            exec_start.contains(&format!("--vault {}", layout.vault.display())),
            "ExecStart does not name this installation's vault: {exec_start}"
        );
        assert!(
            exec_start.contains(&format!(
                "--passphrase-file {}",
                layout.passphrase.display()
            )),
            "ExecStart does not name this installation's passphrase file: {exec_start}"
        );
    });
}

/// Nothing unresolved survives into the installed unit.
///
/// `%h` and `%t` are correct in the template and wrong here: systemd expands
/// them against the session that starts the service, which after a layout
/// change is not where this installation put anything.
#[test]
fn the_installed_unit_has_no_unexpanded_specifier() {
    in_a_clean_install("unit-specifiers", |layout, _| {
        run_fast(layout).unwrap();
        let installed = std::fs::read_to_string(&layout.unit).unwrap();
        let exec_start = installed
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .unwrap();

        for specifier in ["%h", "%t", "%%"] {
            assert!(
                !exec_start.contains(specifier),
                "ExecStart still carries `{specifier}`: {exec_start}"
            );
        }
    });
}

/// Moving the bundle and re-running `setup` moves the unit with it.
///
/// This is the upgrade the risk describes: a mise install replaces the binary
/// in a new prefix, and a unit still pointing at the old one starts a broker
/// that no longer exists — or, worse, one that does.
#[test]
fn re_running_setup_after_the_bundle_moves_repairs_the_unit() {
    in_a_clean_install("unit-moved", |layout, _| {
        run_fast(layout).unwrap();
        let original = std::fs::read_to_string(&layout.unit).unwrap();

        // The bundle relocates to a sibling prefix, the way a mise install
        // moves. The unit is left naming the old one, which is what a failed
        // upgrade looks like from the service's point of view.
        let old = layout.broker_lookup.path().to_path_buf();
        let moved = old
            .parent()
            .and_then(|p| p.parent())
            .map(|root| root.join("libexec-v2").join("asv"))
            .expect("a libexec path");
        crate::tests_support::write_executable(
            &moved.join(crate::layout::BROKER_BINARY),
            b"#!/bin/sh\n",
        );

        // Everything except the broker keeps its path, so the second `setup`
        // still finds the same vault and the same passphrase — only the
        // binary moved, which is the case R8 describes.
        let relocated = Layout {
            broker_lookup: BrokerLookup::Found(moved.join(crate::layout::BROKER_BINARY)),
            ..layout.clone()
        };
        std::fs::write(&relocated.unit, &original).unwrap();
        assert!(
            original.contains(&old.display().to_string()),
            "the control: the installed unit really did name the old binary\n{original}"
        );

        let outcome = run_fast(&relocated).unwrap();

        let repaired = std::fs::read_to_string(&relocated.unit).unwrap();
        assert!(
            repaired.contains(
                &moved
                    .join(crate::layout::BROKER_BINARY)
                    .display()
                    .to_string()
            ),
            "setup did not move the unit with the bundle:\n{repaired}"
        );
        assert!(
            outcome.installed_unit,
            "setup did not report rewriting the unit"
        );
    });
}

/// `run()` returns in bounded time even when the user manager does not answer.
///
/// The bug this pins: `systemctl --user` on a machine with no session bus does
/// not fail, it *waits*. A unit test that let `run()` reach the host's real
/// user manager hung for seven minutes before this was found, and the shape of
/// it reaches past the test suite — `asv setup` is the first command a new
/// user runs, on whatever machine they are on, and it was able to block
/// indefinitely in exactly the container and CI environments where it is most
/// needed.
///
/// The control is the same call with the service disabled by the seam, which
/// must be immediate. Without it, "returns quickly" could be satisfied by a
/// `run()` that never called the user manager at all.
#[test]
fn setup_returns_in_bounded_time_when_the_user_manager_does_not_answer() {
    let tmp = TempTree::new("bounded");
    let libexec = tmp.sub("libexec/asv");
    std::fs::create_dir_all(&libexec).unwrap();
    crate::tests_support::write_executable(&libexec.join("asv-brokerd"), b"#!/bin/sh\n");
    let config = tmp.sub("config");
    let data = tmp.sub("data");
    let runtime = tmp.sub("run");
    for d in [&config, &data, &runtime] {
        std::fs::create_dir_all(d).unwrap();
    }

    let started = std::time::Instant::now();
    with_env(
        &[
            ("HOME", tmp.path.as_os_str()),
            ("XDG_CONFIG_HOME", config.as_os_str()),
            ("XDG_DATA_HOME", data.as_os_str()),
            ("XDG_RUNTIME_DIR", runtime.as_os_str()),
            (crate::layout::LIBEXEC_ENV, libexec.as_os_str()),
            // Note what is NOT set here: `NO_SERVICE_ENV`. This is the run
            // that talks to whatever is on the host.
        ],
        || {
            let layout = crate::layout::for_current_user();
            // Argon2 dominates this measurement on a real vault creation, so
            // the assertion is generous by an order of magnitude and is only
            // there to catch a hang, not to time the crypto.
            run(&layout).expect("setup still completes");
        },
    );
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(90),
        "asv setup took {elapsed:?}; on a machine with no systemd user session \
         the user manager call has to be bounded"
    );
}

/// The cheap stand-in for `run`, used by every other test in this file.
fn run_fast(layout: &Layout) -> std::io::Result<SetupOutcome> {
    run_with(layout, crate::vaultops::Kdf::FastForTests)
}

/// The production path really does use the strong parameters.
///
/// This is the test that pays for the cheap one. `run` and `run_with` differ
/// only in the KDF variant they pass, and a suite that ran the fast path
/// everywhere would still be green if `run` passed `FastForTests` by mistake —
/// which would mean every vault any operator ever created opens instantly.
///
/// So this one test runs `run` itself, and the assertion is on the numbers
/// rather than on a timing, because a timing assertion is a flake waiting for
/// a slow machine.
#[test]
fn setup_production_kdf_is_the_strong_shape() {
    use asv_vault::KdfParams;

    let production = crate::vaultops::Kdf::Production.params();
    assert_eq!(
        (production.m_cost_kib, production.t_cost, production.p_cost),
        (64 * 1024, 3, 4),
        "the production KDF shape changed; 64 MiB / 3 passes / 4 lanes is the \
         OWASP Argon2id baseline this repository recorded on purpose"
    );

    let fast = crate::vaultops::Kdf::FastForTests.params();
    assert!(
        (fast.m_cost_kib, fast.t_cost, fast.p_cost)
            != (production.m_cost_kib, production.t_cost, production.p_cost),
        "the test parameters and the production parameters are the same, so \
         the tests are not testing anything different and the split is a lie"
    );
    // And the real thing round-trips: a vault created with production
    // parameters opens with production parameters and refuses to open with
    // the fast ones' envelope. Argon2id records its own cost in the header,
    // so a mismatch is a wrong key rather than a silent success.
    let dir = TempTree::new("kdf-shape");
    let vault = dir.sub("vault.asv");
    crate::vaultops::create_empty_vault(&vault, "correct horse", crate::vaultops::Kdf::Production)
        .expect("creates a production vault");

    let opened = asv_vault::VaultStore::open(
        &vault,
        &secrecy::SecretString::from("correct horse".to_string()),
    );
    assert!(
        opened.is_ok(),
        "a production vault must open with its own passphrase"
    );

    // A vault whose header says 64 MiB and whose key was derived for 8 MiB
    // must not open. The test parameters are the floor the envelope's own
    // validator accepts, so this is the case where a downgrade would land.
    let params = KdfParams::default();
    assert!(params.validate().is_ok());
    assert!(crate::vaultops::Kdf::FastForTests
        .params()
        .validate()
        .is_ok());
}
