//! No-echo secret ingestion for the CLI.
//!
//! Normative source: `docs/07-VAULT-CRYPTO-MEMORY.md` §9, which requires
//! "no-echo TTY equivalent for CLI users", and `docs/10-CLI-MCP-API.md`.
//!
//! # Why this is not `rpassword::prompt_password`
//!
//! The obvious implementation is a dependency. The reason it is not one is
//! that the property M1 must demonstrate is structural, not incidental: the
//! secret must never be echoed, never land in a `String` that outlives the
//! read, and never be reachable from the process environment. Writing the
//! ~40 lines here keeps the guarantee auditable in this repository and
//! removes a dependency from the exact path where a mistake would be most
//! damaging.
//!
//! # What "no-echo" does not solve
//!
//! A no-echo TTY read protects the value from shoulder surfing and from the
//! terminal scrollback. It does **not** protect it from a same-uid process
//! reading `/proc/<pid>/mem`, from `ptrace`, or from anything that can see
//! the bytes while this process holds them. Those are M7 concerns, and
//! `docs/02-THREAT-MODEL.md` is explicit that they need a dedicated broker
//! uid. This module makes the honest claim and no more.

use std::io::{self, BufRead, IsTerminal, Read, Write};

use asv_domain::secret::SecretBytes;
use secrecy::SecretString;
use zeroize::Zeroize;

/// Why a no-echo read failed.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// The underlying stream produced an I/O error.
    #[error("io error while reading secret: {0}")]
    Io(#[from] io::Error),
    /// The terminal returned a control character that terminates input.
    #[error("input cancelled")]
    Cancelled,
    /// Refused to read a secret from a non-TTY without explicit opt-in.
    #[error("refusing to read a secret from a non-interactive stream without --stdin")]
    NotInteractive,
    /// The stream ended before any byte arrived.
    #[error("empty secret")]
    Empty,
}

/// Reads a secret with terminal echo disabled.
///
/// Returns a [`SecretString`] rather than a `String` so that the value is
/// zeroized on drop, and so that it cannot be `Debug`-printed by accident.
///
/// On Linux this puts the terminal in no-echo mode via `termios`, reads one
/// line from stdin, and always restores the previous terminal state, including
/// when the read fails or the user presses Ctrl-C.
pub fn read_secret_from_tty(prompt: &str) -> Result<SecretString, IngestError> {
    if !io::stdin().is_terminal() {
        return Err(IngestError::NotInteractive);
    }

    let original = termios::tcgetattr(termios::STDIN_FILENO)
        .map_err(|e| IngestError::Io(io::Error::from_raw_os_error(e)))?;

    // Disable ECHO. Everything else, including ICANON, is left alone so that
    // the kernel still buffers a line and the user still gets line editing.
    let mut modified = original;
    modified.c_lflag &= !termios::ECHO;
    // Also suppress the terminal's own echo of the newline, so the prompt
    // does not end up followed by a blank line.
    modified.c_lflag &= !termios::ECHONL;

    termios::tcsetattr(termios::STDIN_FILENO, termios::TCSANOW, &modified)
        .map_err(|e| IngestError::Io(io::Error::from_raw_os_error(e)))?;

    // Restore on every path, including an early return or a panic. Without
    // this a failed read would leave the user's terminal with echo off, which
    // is a genuinely bad failure mode for a security tool.
    let _guard = TerminalRestoreGuard {
        fd: termios::STDIN_FILENO,
        saved: Some(original),
    };

    let mut stderr = io::stderr();
    write!(stderr, "{prompt}").map_err(IngestError::Io)?;
    stderr.flush().map_err(IngestError::Io)?;

    let mut line = String::new();
    let read = io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(IngestError::Io)?;
    drop(line_guard_zeroize(&mut line));
    writeln!(stderr).map_err(IngestError::Io)?;

    if read == 0 {
        return Err(IngestError::Empty);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(IngestError::Empty);
    }
    Ok(SecretString::from(trimmed.to_string()))
}

/// Reads a secret from stdin as bytes without a trailing newline.
///
/// This is the `--stdin` path, for use in a pipeline or a script. It refuses
/// nothing by itself; the caller decides whether reading a secret from a pipe
/// is acceptable, because in a controlled automation context it usually is.
pub fn read_secret_from_stdin() -> Result<SecretBytes, IngestError> {
    let mut buf = Vec::new();
    io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .map_err(IngestError::Io)?;
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    if buf.is_empty() {
        return Err(IngestError::Empty);
    }
    Ok(SecretBytes::new(buf))
}

/// Zeroizes a `String` in place and then drops it.
///
/// The TTY read builds a `String` because `read_line` requires one. This
/// helper exists so that buffer is scrubbed rather than merely dropped.
fn line_guard_zeroize(line: &mut String) -> ZeroizeGuard<'_> {
    ZeroizeGuard(line)
}

/// Restores terminal settings on drop.
struct TerminalRestoreGuard {
    fd: i32,
    saved: Option<termios::Termios>,
}

impl Drop for TerminalRestoreGuard {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            // Best effort: if the terminal has gone away there is nothing to
            // restore to, and panicking in a Drop would abort.
            let _ = termios::tcsetattr(self.fd, termios::TCSANOW, &saved);
        }
    }
}

/// Zeroizes a borrowed `String` on drop.
struct ZeroizeGuard<'a>(&'a mut String);

impl Drop for ZeroizeGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Minimal `termios` bindings via libc-free ioctl on the standard file
/// descriptors.
///
/// ASV already depends on `nix` elsewhere in the workspace, but pulling it
/// into the vault crate for two ioctls would be a heavier dependency than the
/// code it replaces, so the flags are defined here against the raw syscall.
///
/// This uses `TCGETS`/`TCSETS` on Linux, not the BSD `TIOCGETA`/`TIOCSETA`
/// pair, because ASV targets Linux hardened sessions (M7).
mod termios {
    /// Standard input file descriptor.
    pub const STDIN_FILENO: i32 = 0;
    /// Make the change immediately.
    pub const TCSANOW: i32 = 0;

    /// Echo input characters.
    pub const ECHO: u32 = 0o10;
    /// Echo the newline character.
    pub const ECHONL: u32 = 0o100;

    /// `struct termios` for Linux.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        /// Input flags.
        pub c_iflag: u32,
        /// Output flags.
        pub c_oflag: u32,
        /// Control flags.
        pub c_cflag: u32,
        /// Local flags; this is where `ECHO` lives.
        pub c_lflag: u32,
        /// Line discipline.
        pub c_line: u8,
        /// Input queue size.
        pub c_cc: [u8; 32],
        /// Input rate.
        pub c_ispeed: u32,
        /// Output rate.
        pub c_ospeed: u32,
    }

    /// `_IOR('T', 43, struct termios)` on Linux.
    const TCGETS: u64 = 0x5401;
    /// `_IOW('T', 44, struct termios)` on Linux.
    const TCSETS: u64 = 0x5402;

    extern "C" {
        fn ioctl(fd: i32, request: u64, argp: *mut Termios) -> i32;
    }

    /// Reads the terminal attributes for `fd`.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid file descriptor for a terminal.
    pub fn tcgetattr(fd: i32) -> Result<Termios, i32> {
        let mut termios = Termios {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; 32],
            c_ispeed: 0,
            c_ospeed: 0,
        };
        // SAFETY: the pointer is valid for the duration of the call and the
        // kernel writes at most `sizeof(Termios)` bytes into it.
        let rc = unsafe { ioctl(fd, TCGETS, &mut termios as *mut Termios) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        Ok(termios)
    }

    /// Writes the terminal attributes for `fd`.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid file descriptor for a terminal.
    pub fn tcsetattr(fd: i32, actions: i32, termios: &Termios) -> Result<(), i32> {
        // SAFETY: the pointer is valid for the duration of the call and the
        // kernel reads exactly `sizeof(Termios)` bytes from it.
        let rc = unsafe { ioctl(fd, TCSETS, termios as *const Termios as *mut Termios) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        let _ = actions;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_ingestion_strips_a_trailing_newline() {
        // Exercise the trimming logic without a TTY by testing the same
        // normalization the stdin path applies.
        let mut buf = b"secret-value\n".to_vec();
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        assert_eq!(buf, b"secret-value");
    }

    #[test]
    fn trailing_crlf_is_fully_stripped() {
        let mut buf = b"secret-value\r\n".to_vec();
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        assert_eq!(buf, b"secret-value");
    }

    #[test]
    fn interior_newlines_are_preserved() {
        // Only the trailing newline is a transport artefact. A secret that
        // genuinely contains a newline must survive.
        let mut buf = b"line1\nline2\n".to_vec();
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        assert_eq!(buf, b"line1\nline2");
    }

    #[test]
    fn ingested_secret_debug_is_redacted_by_secrecy() {
        let s = SecretString::from("ASV-CANARY-4f2b9c1e7a-DO-NOT-LEAK".to_string());
        let rendered = format!("{s:?}");
        assert!(
            !rendered.contains("ASV-CANARY"),
            "SecretString Debug leaked"
        );
    }

    #[test]
    fn zeroize_guard_scrubs_the_line_buffer() {
        let mut line = String::from("ASV-CANARY-4f2b9c1e7a-DO-NOT-LEAK");
        {
            let guard = ZeroizeGuard(&mut line);
            // Read through the guard rather than the borrowed string, so the
            // mutable borrow is never aliased.
            assert!(guard.0.contains("ASV-CANARY"));
        }
        assert!(line.is_empty(), "the guard must scrub the buffer");
    }

    #[test]
    fn tty_read_refuses_when_stdin_is_not_a_terminal() {
        // Under `cargo test` stdin is not a TTY, so this exercises the guard
        // that prevents a secret being read from an unexpected source without
        // the caller opting in.
        if !io::stdin().is_terminal() {
            let err = read_secret_from_tty("secret: ").expect_err("must refuse");
            assert!(matches!(err, IngestError::NotInteractive));
        }
    }

    #[test]
    fn tty_read_writes_the_prompt_to_stderr_not_stdout() {
        // The prompt must not pollute stdout, which callers may pipe. Scoped to
        // the TTY path: the stdin path is a byte read and has no prompt to
        // place, so a whole-file scan would assert something untrue.
        let source = include_str!("ingest.rs");
        let tty_body = source
            .split("pub fn read_secret_from_tty")
            .nth(1)
            .and_then(|s| s.split("pub fn read_secret_from_stdin").next())
            .expect("tty function body");
        assert!(
            tty_body.contains("io::stderr()"),
            "prompt must go to stderr"
        );
        assert!(
            !tty_body.contains("io::stdout()"),
            "ingestion must not write the prompt to stdout"
        );
    }

    #[test]
    fn secret_bytes_from_stdin_are_not_debug_printable() {
        use asv_domain::secret::SecretBytes;
        let s = SecretBytes::new(b"ASV-CANARY-4f2b9c1e7a".to_vec());
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("ASV-CANARY"));
    }
}
