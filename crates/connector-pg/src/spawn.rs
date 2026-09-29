//! The `spawn_psql` helper (M6-R2).
//!
//! The rule, stated once and implemented once:
//!
//! > The broker hands the password to `psql` *after* `psql` has opened
//! > the TCP socket, via a stdin pipe. The password never appears in
//! > the agent's environment, command line, argv, or any file the agent
//! > writes.
//!
//! The helper builds a `tokio::process::Command` that:
//!
//!  1. clears the parent environment (`env_clear`),
//!  2. sets `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER` to non-secret
//!     values the broker has approved,
//!  3. deliberately does NOT set `PGPASSWORD` or `PGPASSFILE`,
//!  4. opens stdin as `Stdio::piped()` so the caller can write the
//!     password after spawn,
//!  5. captures stdout/stderr (the agent must not see them).
//!
//! The companion function `spawn_psql_reveal` is a test-only helper
//! that intentionally leaks the resulting environment and argv, so a
//! test can grep for the password and confirm it is not there.

use std::process::Stdio;
use tokio::process::Command;

/// What the broker needs to spawn `psql`.
#[derive(Debug, Clone)]
pub struct PsqlSpawn {
    /// The host `psql` will reach (the resolved authority).
    pub host: String,
    /// The port `psql` will reach.
    pub port: u16,
    /// The database `psql` will request.
    pub database: String,
    /// The role `psql` will authenticate as.
    pub role: String,
    /// The path to the `psql` binary. Defaults to `psql` in PATH.
    pub program: Option<String>,
}

impl PsqlSpawn {
    /// Builds the broker-side command. The password is *not* an input:
    /// the helper opens stdin as `Stdio::piped()` and the caller writes
    /// the password to it after the process has started.
    ///
    /// This function is safe to call from production code. There is no
    /// environment read, no `which`, no fallback to `~/.pgpass`.
    pub fn build_command(&self) -> Command {
        let mut cmd = Command::new(self.program.as_deref().unwrap_or("psql"));
        cmd.env_clear();
        cmd.env("PGHOST", &self.host);
        cmd.env("PGPORT", self.port.to_string());
        cmd.env("PGDATABASE", &self.database);
        cmd.env("PGUSER", &self.role);
        // PGPASSWORD and PGPASSFILE are intentionally not set.
        cmd.arg("--no-password");
        cmd.arg("--quiet");
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }
}

/// Test-only: the same build, plus a `--` so a wrapper script can dump
/// its environment and argv for inspection.
///
/// The wrapper script is a no-op on a normal Linux box (`cat` exists);
/// the helper exists so the test can pick it up and verify the four
/// forbidden locations are empty.
///
/// Exposed unconditionally (not `#[cfg(test)]`) so the broker's
/// integration test (UAT-039) can introspect the same `Command`
/// without re-implementing the env_clear logic.
pub fn spawn_psql_reveal(spawn: &PsqlSpawn, wrapper: &str) -> Command {
    let mut cmd = spawn.build_command();
    cmd.arg("--");
    cmd.arg(wrapper);
    cmd
}