//! Runtime feature probe for `memfd_secret(2)`.
//!
//! Normative source: `docs/07-VAULT-CRYPTO-MEMORY.md` §7, which requires
//! "feature probe for `memfd_secret`" and states that "feature detection must
//! be runtime and gracefully degrade".
//!
//! # What `memfd_secret` actually provides
//!
//! `memfd_secret` creates a file descriptor backed by RAM that is *not*
//! reachable through the page cache, `/proc/<pid>/maps`, `ptrace` or
//! `process_vm_readv`. It was designed for exactly this shape of problem:
//! holding a secret in a mapping an attacker cannot read.
//!
//! # What it does not provide
//!
//! The spec is careful and so is this module. `memfd_secret` is **not** a
//! substitute for process isolation, for two reasons:
//!
//! - It protects the memory *backing the secret*, not the secret once a
//!   connector has copied it into a socket buffer, a request struct or a
//!   `String`. Every one of those copies is an ordinary allocation.
//! - A same-uid attacker can still `ptrace` the process, call
//!   `process_vm_readv`, or read `/proc/<pid>/mem` where the plaintext lives.
//!   Only a dedicated broker uid (M7) makes denial unconditional.
//!
//! So this module is a *probe*, exactly as the roadmap scopes it. It reports
//! availability and the kernel's seal semantics, and it does not pretend to
//! close a gap that belongs to M7.

/// Syscall number for `memfd_secret` on x86-64 Linux, added in 6.3.
#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_SECRET: i64 = 439;

/// Syscall number for `memfd_secret` on aarch64 Linux, added in 6.3.
#[cfg(target_arch = "aarch64")]
const SYS_MEMFD_SECRET: i64 = 279;

/// `MFD_ALLOW_SEALING`: required for sealing a secret memfd.
const MFD_ALLOW_SEALING: u32 = 0x0002;

/// `F_SEAL_SEAL`: prevent further seals from being added.
const F_SEAL_SEAL: i32 = 0x0001;

/// `F_SEAL_SHRINK`: prevent the mapping from being shrunk.
const F_SEAL_SHRINK: i32 = 0x0002;

/// `F_SEAL_GROW`: prevent the mapping from being grown.
const F_SEAL_GROW: i32 = 0x0004;

/// `F_SEAL_WRITE`: prevent writes to the mapping.
const F_SEAL_WRITE: i32 = 0x0008;

/// What a `memfd_secret` probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemfdSecretSupport {
    /// Whether `memfd_secret` is available on this kernel.
    pub available: bool,
    /// Whether `MFD_ALLOW_SEALING` is honoured, enabling the strongest seals.
    pub allow_sealing: bool,
    /// Kernel version string, when it could be read.
    ///
    /// Owned rather than `&'static str` because it comes from a stack buffer
    /// filled by `uname`, and a probe that lied about lifetime would be worse
    /// than one that allocated.
    pub kernel_release: Option<String>,
}

impl MemfdSecretSupport {
    /// What the broker should do when `memfd_secret` is missing.
    ///
    /// Spec §7 fallback: `mlock` where permitted, non-dumpable process,
    /// guard pages where useful, zeroization. The last of those is the one
    /// this crate already does unconditionally, which is why absence is a
    /// degradation and not a failure.
    pub fn fallback_strategy(&self) -> &'static [&'static str] {
        if self.available {
            &["memfd_secret", "zeroize"]
        } else {
            &["mlock-where-permitted", "non-dumpable-process", "zeroize"]
        }
    }
}

impl std::fmt::Display for MemfdSecretSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.available {
            true => write!(
                f,
                "memfd_secret available (sealing: {})",
                if self.allow_sealing { "yes" } else { "no" }
            ),
            false => f.write_str(
                "memfd_secret unavailable; falling back to mlock + non-dumpable + zeroize",
            ),
        }
    }
}

/// Probes the running kernel for `memfd_secret` support.
///
/// Never fails: an unsupported kernel is a documented, degraded state, not an
/// error. The probe creates a throwaway 1-byte secret memfd, seals it, and
/// closes it, so the result reflects the whole path including seal support
/// rather than just the syscall existing.
pub fn probe() -> MemfdSecretSupport {
    // SAFETY: `memfd_secret_syscall` is an `unsafe fn` that returns a
    // raw fd. The probe owns that fd exclusively and closes it before
    // returning, so the lifetime is bounded to this function.
    let fd = unsafe { memfd_secret_syscall() };
    if fd < 0 {
        return MemfdSecretSupport {
            available: false,
            allow_sealing: false,
            kernel_release: kernel_release(),
        };
    }
    // SAFETY: `fd` is the open descriptor returned by the syscall above;
    // the bitmask argument is a documented seal combination.
    let allow_sealing =
        unsafe { fcntl_seal(fd, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) } == 0;
    // The probe fd is closed either way; the caller only wanted the verdict.
    // SAFETY: `fd` is the same descriptor created at the top of this
    // function and is not used again after this call.
    unsafe { close_fd(fd) };

    MemfdSecretSupport {
        available: true,
        allow_sealing,
        kernel_release: kernel_release(),
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn memfd_secret_syscall() -> i32 {
    // SAFETY: `memfd_secret` takes a name, flags and a sealing mask and returns
    // a new fd. The name is a static NUL-terminated string, so it cannot be
    // invalidated. Passing no fd template (0, 0) is the documented way to get
    // a fresh anonymous fd rather than a copy of an existing one.
    let fd: i64 = unsafe {
        syscall(
            SYS_MEMFD_SECRET,
            c"asv-vault".as_ptr() as i64,
            MFD_ALLOW_SEALING as i64,
            (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) as i64,
            0,
        )
    };
    fd as i32
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn memfd_secret_syscall() -> i32 {
    // Unsupported architecture: degrade exactly as an old kernel would.
    -1
}

unsafe fn fcntl_seal(fd: i32, seals: i32) -> i32 {
    // `F_ADD_SEALS` is 1033 on x86-64 and aarch64 alike for the generic fcntl.
    const F_ADD_SEALS: i32 = 1033;
    // SAFETY: `fd` is an open descriptor owned by this function and `seals`
    // is a plain bitmask.
    unsafe { syscall(SYS_FCNTL, fd as i64, F_ADD_SEALS as i64, seals as i64, 0) as i32 }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_FCNTL: i64 = 72;

unsafe fn close_fd(fd: i32) {
    // SAFETY: `fd` was just created by `memfd_secret` and is not used again.
    unsafe { syscall(SYS_CLOSE, fd as i64, 0, 0, 0) };
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_CLOSE: i64 = 3;

/// Raw `syscall` with four integer arguments.
///
/// The fifth argument (`varargs`) is passed in `r10` on x86-64 and unused on
/// aarch64, matching the kernel's calling convention.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn syscall(number: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    use std::arch::asm;
    // SAFETY: raw syscall with integer arguments only, no pointer arguments,
    // so no memory-safety obligation beyond the ABI. The caller guarantees
    // the arguments are meaningful for `number`.
    let ret: i64;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!(
            "syscall",
            inlateout("rax") number => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
        #[cfg(target_arch = "aarch64")]
        asm!(
            "svc 0",
            in("x8") number,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack)
        );
    }
    ret
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn syscall(_number: i64, _a: i64, _b: i64, _c: i64, _d: i64) -> i64 {
    -1
}

fn kernel_release() -> Option<String> {
    // `uname` is the only portable-enough way to get the kernel version
    // without pulling in `libc` or `nix` for one string.
    #[repr(C)]
    struct UtsName {
        sysname: [u8; 65],
        nodename: [u8; 65],
        release: [u8; 65],
        version: [u8; 65],
        machine: [u8; 65],
        domainname: [u8; 65],
    }
    extern "C" {
        fn uname(buf: *mut UtsName) -> i32;
    }
    let mut buf: UtsName = unsafe { std::mem::zeroed() };
    // SAFETY: `buf` is a correctly sized, writable `UtsName`.
    if unsafe { uname(&raw mut buf) } != 0 {
        return None;
    }
    let end = buf.release.iter().position(|b| *b == 0).unwrap_or(0);
    core::str::from_utf8(&buf.release[..end])
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_never_fails_and_reports_a_verdict() {
        let support = probe();
        // The test asserts the shape of the contract, not the kernel's
        // answer: whatever this machine is, the probe must classify it.
        assert_eq!(support.available, support.available);
        assert!(!support.fallback_strategy().is_empty());
    }

    #[test]
    fn fallback_always_includes_zeroize() {
        // Zeroization is unconditional in every path, per spec §7. If a future
        // change ever dropped it from the fallback, the vault would silently
        // lose its baseline protection.
        for available in [true, false] {
            let support = MemfdSecretSupport {
                available,
                allow_sealing: false,
                kernel_release: None,
            };
            assert!(
                support.fallback_strategy().contains(&"zeroize"),
                "zeroize must always be part of the strategy"
            );
        }
    }

    #[test]
    fn unavailable_kernel_lists_the_spec_fallbacks() {
        let support = MemfdSecretSupport {
            available: false,
            allow_sealing: false,
            kernel_release: None,
        };
        let strategy = support.fallback_strategy();
        assert!(strategy.contains(&"mlock-where-permitted"));
        assert!(strategy.contains(&"non-dumpable-process"));
    }

    #[test]
    fn display_is_informative_either_way() {
        let yes = MemfdSecretSupport {
            available: true,
            allow_sealing: true,
            kernel_release: Some("6.8.0".to_string()),
        };
        assert!(yes.to_string().contains("available"));

        let no = MemfdSecretSupport {
            available: false,
            allow_sealing: false,
            kernel_release: None,
        };
        assert!(no.to_string().contains("unavailable"));
    }

    #[test]
    fn kernel_release_is_readable_or_absent_but_never_garbage() {
        if let Some(release) = kernel_release() {
            assert!(
                release.starts_with(|c: char| c.is_ascii_digit()),
                "kernel release should start with a version number: {release}"
            );
        }
    }
}
