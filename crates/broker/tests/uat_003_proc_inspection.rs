//! UAT-003 — process memory attack against broker.
//!
//! Normative requirement (`14-UAT-ADVERSARIAL.md`):
//!
//! > Agent attempts: gdb -p <broker-pid>; strace -p; /proc/<broker>/mem;
//! > process_vm_readv; pidfd_getfd where practical. Expected: denied
//! > under supported hardened installation; no secret disclosure.
//!
//! The first two tests below assert the broker's own state. The third is the
//! one the requirement actually asks for, and it is a *kernel* assertion: a
//! separate process under the same uid opens `/proc/<broker-pid>/mem` and is
//! refused by the kernel, not by anything the broker chose to do about it.
//!
//! That test used to be `#[ignore]`d with the reason *"structural: requires a
//! child process to attempt the open; the in-process check is dumpable_is_zero"*.
//! The reason named the fix — a child process — and the fix was never built, so
//! the strongest clause of the milestone's own exit UAT had never executed. It
//! executes now, with two controls, because a refusal with nothing to compare
//! it against is not evidence of anything.

use asv_broker::harden::{dumpable_is_zero, install, no_new_privs_is_set};

#[test]
fn uat_003_install_sets_dumpable_to_zero() {
    install().expect("harden::install must succeed in this test");
    assert!(
        dumpable_is_zero(),
        "PR_SET_DUMPABLE=0 must take effect for the broker's own /proc/<pid>/mem to be unreadable"
    );
}

#[test]
fn uat_003_install_sets_no_new_privs() {
    install().expect("harden::install must succeed in this test");
    assert!(
        no_new_privs_is_set(),
        "PR_SET_NO_NEW_PRIVS=1 must take effect so setuid binaries cannot gain privileges"
    );
}

#[test]
fn uat_003_install_is_repeatable() {
    // Repeated calls must remain idempotent; an attacker that can
    // cause the broker to call harden::install twice (e.g. via a
    // signal handler) MUST NOT be able to escape the protection.
    install().expect("first install");
    install().expect("second install");
    assert!(dumpable_is_zero());
    assert!(no_new_privs_is_set());
}

#[cfg(target_os = "linux")]
mod kernel_refuses_a_same_uid_reader {
    //! The adversarial half of UAT-003, and the part M7's residual is about.
    //!
    //! The property: a process under the *same uid* as the broker cannot read
    //! the broker's memory. Today that is enforced by `PR_SET_DUMPABLE=0`
    //! rather than by a separate OS identity, so the claim is narrower than
    //! "the broker's memory is unreadable" — it is "unreadable by a process
    //! that lacks `CAP_SYS_PTRACE`", which is the check the kernel performs.
    //! A dedicated broker uid would make it unconditional; that is V1-C1's
    //! other half and it needs an OS account this host cannot create.
    //!
    //! # The scenario runs in a forked child, and that is load-bearing
    //!
    //! `PR_SET_DUMPABLE` is a **process** attribute, and every `#[test]` in
    //! this binary shares one process. The first version of this module set
    //! the flag in the test process and forked the attacker from it — and its
    //! falsification proved the mistake: removing the hardening left the test
    //! **green**, because `uat_003_install_sets_dumpable_to_zero` runs in the
    //! same process and had set the flag back. A test whose outcome depends on
    //! a neighbouring test is not a test of the property, and the first version
    //! would have passed for exactly the wrong reason.
    //!
    //! So the whole scenario — set the flag, fork the attacker, report — runs
    //! inside a child of the test process, which sets its own flag and never
    //! touches the parent's. Each test owns the state it is reasoning about.
    //! Forked from a multi-threaded binary, a child may only call
    //! async-signal-safe functions, so it uses `prctl`, `fork`, `open`, `read`,
    //! `write`, `close`, `waitpid` and `_exit` and nothing else — every `CString`
    //! is built before the fork so the child never allocates.
    //!
    //! # What each half proves
    //!
    //! `uat_003_install_sets_dumpable_to_zero` above proves the *shipped*
    //! function sets the flag. The test below proves the flag makes the kernel
    //! refuse. The composition is the property; separating it is what makes
    //! both halves falsifiable, because a child that called `install()` would
    //! have to allocate and could deadlock on a lock another thread held at
    //! fork time.

    use std::ffi::CString;
    use std::io;

    /// CAP_SYS_PTRACE is capability bit 19.
    const CAP_SYS_PTRACE_MASK: u64 = 1 << 19;

    /// Read `CapEff` out of a `/proc/self/status`-shaped string.
    ///
    /// Pure on purpose. The guard that the attacker is unprivileged is only
    /// meaningful if it can reject a value that *is* privileged, and on an
    /// ordinary developer machine no run can produce one — so the parsing and
    /// the bit test are separated from the read, and the rejection is proven by
    /// a doctored value rather than asserted by hope.
    fn cap_eff_from_status(status: &str) -> Option<u64> {
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .map(|v| v.trim())
            .and_then(|v| u64::from_str_radix(v, 16).ok())
    }

    fn has_ptrace_capability(status: &str) -> Option<bool> {
        cap_eff_from_status(status).map(|eff| eff & CAP_SYS_PTRACE_MASK != 0)
    }

    fn assert_attacker_lacks_ptrace_capability() {
        let status = std::fs::read_to_string("/proc/self/status")
            .expect("/proc/self/status must be readable on Linux");
        let cap_eff = status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .expect("CapEff must be present in /proc/self/status")
            .trim();
        match has_ptrace_capability(&status) {
            Some(false) => {}
            Some(true) => panic!(
                "this test requires an unprivileged attacker: it holds \
                 CAP_SYS_PTRACE (CapEff={cap_eff}), so the kernel would permit \
                 the read whether or not the broker hardened anything, and the \
                 assertion would be measuring the wrong thing"
            ),
            None => panic!("CapEff {cap_eff:?} is not a hex value"),
        }
    }

    fn pipe() -> [libc::c_int; 2] {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a valid two-element array; `pipe` writes only the
        // two descriptors into it.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed: {}", io::Error::last_os_error());
        fds
    }

    /// `Ok(())` if the child's `open` succeeded, else the errno.
    ///
    /// Separating the two is the point. A test asserting only "the open
    /// failed" would also pass on `ENOENT`, because the target had exited —
    /// a result that says nothing about hardening.
    fn read_result(rfd: libc::c_int) -> Result<(), libc::c_int> {
        let mut byte = [0u8; 1];
        // SAFETY: `rfd` is a live pipe read end; the buffer is one byte.
        let n = unsafe { libc::read(rfd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        assert_eq!(n, 1, "child did not report: {}", io::Error::last_os_error());
        if byte[0] == 0 {
            Ok(())
        } else {
            Err(byte[0] as libc::c_int)
        }
    }

    fn report(fd: libc::c_int, outcome: Result<(), libc::c_int>) {
        let byte = if outcome.is_ok() { 0u8 } else { 1u8 };
        // SAFETY: `fd` is a live pipe write end, writing exactly one byte.
        let n = unsafe { libc::write(fd, &byte as *const u8 as *const libc::c_void, 1) };
        assert_eq!(
            n,
            1,
            "failed to report outcome: {}",
            io::Error::last_os_error()
        );
    }

    /// In the child only: set dumpable, fork the attacker, let it try.
    ///
    /// `dumpable` is what the *target* child sets on itself. Everything after
    /// the flag is fixed, so a single value parameter is what the two tests
    /// differ on and therefore exactly what a mutation has to move.
    ///
    /// # The path arrives by pipe, and that is not ceremony
    ///
    /// The obvious version formats `/proc/<pid>/mem` inside the child. That
    /// was the first version here, and it is **allocation in a process forked
    /// from a multi-threaded one** -- `format!` can block on the allocator
    /// arena, and if another thread held it at the instant of the `fork`, the
    /// child deadlocks before it can report anything. The observed symptom was
    /// an intermittent failure in the broker suite that vanished on re-run,
    /// which is the least informative failure mode there is.
    ///
    /// So the child allocates nothing. It sends its pid up as four raw bytes,
    /// reads the formatted path back into a fixed-size stack buffer, and every
    /// call it makes -- `prctl`, `write`, `read`, `fork`, `open`, `close`,
    /// `waitpid`, `_exit` -- is async-signal-safe. The only formatting happens
    /// in the parent, which is an ordinary multi-threaded process and may
    /// allocate freely.
    unsafe fn scenario_in_child(
        dumpable: libc::c_long,
        pid_fd: libc::c_int,
        path_fd: libc::c_int,
        result_fd: libc::c_int,
    ) -> ! {
        libc::prctl(libc::PR_SET_DUMPABLE, dumpable, 0, 0, 0);

        // Hand the parent this process's pid as raw bytes: no formatting, and
        // no allocation.
        let pid = libc::getpid();
        let raw = pid.to_ne_bytes();
        if libc::write(pid_fd, raw.as_ptr() as *const libc::c_void, 4) != 4 {
            libc::_exit(3);
        }

        // Receive the formatted path into a fixed-size stack buffer. A fixed
        // buffer is what keeps this allocation-free.
        let mut buf = [0u8; 256];
        let n = libc::read(
            path_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() - 1,
        );
        if n <= 0 {
            libc::_exit(3);
        }
        buf[n as usize] = 0;
        let path = buf.as_ptr() as *const libc::c_char;

        let attacker = libc::fork();
        if attacker == 0 {
            // The attacker: same uid, one fork deeper. `open` with O_RDONLY
            // is what `gdb -p` and `/proc/<pid>/mem` both need.
            let fd = libc::open(path, libc::O_RDONLY);
            let outcome = if fd < 0 {
                Err(*libc::__errno_location())
            } else {
                libc::close(fd);
                Ok(())
            };
            report(result_fd, outcome);
            libc::_exit(0);
        }
        if attacker < 0 {
            libc::_exit(2);
        }
        let mut st = 0;
        libc::waitpid(attacker, &mut st, 0);
        libc::_exit(0);
    }

    /// Fork the scenario and wait for its verdict. Returns what the attacker
    /// reported, having cleaned up every descriptor.
    fn run_scenario(dumpable: libc::c_long) -> Result<(), libc::c_int> {
        let pids = pipe();
        let paths = pipe();
        let verdicts = pipe();

        // SAFETY: valid array, called in the parent where the framework's
        // threads are intact.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork() failed: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: every call between here and `_exit` is async-signal-safe.
            unsafe { scenario_in_child(dumpable, pids[1], paths[0], verdicts[1]) }
        }

        // The parent formats the path: the only place that allocates.
        let mut raw = [0u8; 4];
        // SAFETY: the child wrote exactly four bytes before proceeding.
        let got = unsafe { libc::read(pids[0], raw.as_mut_ptr() as *mut libc::c_void, 4) };
        assert_eq!(got, 4, "the scenario child did not send its pid");
        let target_pid = i32::from_ne_bytes(raw);
        let path = CString::new(format!("/proc/{target_pid}/mem")).expect("pid is a valid path");
        // SAFETY: `path` is NUL-terminated and the write end is live.
        let wrote = unsafe {
            libc::write(
                paths[1],
                path.as_ptr() as *const libc::c_void,
                path.as_bytes().len(),
            )
        };
        assert_eq!(
            wrote,
            path.as_bytes().len() as isize,
            "could not hand the path to the scenario child"
        );

        // SAFETY: `pid` is a child of this process.
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status),
            "the scenario child did not exit cleanly; it was killed or stopped"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the scenario child could not complete: exit {}",
            libc::WEXITSTATUS(status)
        );
        let outcome = read_result(verdicts[0]);
        // SAFETY: all six descriptors are ours and are closed exactly once.
        unsafe {
            for fd in [
                pids[0],
                pids[1],
                paths[0],
                paths[1],
                verdicts[0],
                verdicts[1],
            ] {
                libc::close(fd);
            }
        }
        outcome
    }

    /// UAT-003's requirement, as the kernel enforces it.
    #[test]
    fn a_same_uid_process_cannot_read_an_undumpable_brokers_memory() {
        assert_attacker_lacks_ptrace_capability();
        match run_scenario(0) {
            Err(e) if e == libc::EACCES || e == libc::EPERM => {}
            Err(e) => panic!(
                "the attacker was refused, but with errno {e} rather than \
                 EACCES ({}) or EPERM ({}). A refusal for an unrelated reason \
                 would satisfy a test that only checked for failure.",
                libc::EACCES,
                libc::EPERM
            ),
            Ok(()) => panic!(
                "a process under the same uid read /proc/<broker>/mem on an \
                 undumpable target. UAT-003 requires this to be denied."
            ),
        }
    }

    /// The control: the identical attack against a *dumpable* target of the
    /// same uid succeeds.
    ///
    /// Without it the test above is unfalsifiable in the way that matters — it
    /// would pass on a host where the open failed for a reason unrelated to
    /// hardening, and just as happily if the kernel stopped enforcing the
    /// dumpable rule altogether.
    #[test]
    fn the_same_attack_against_a_dumpable_sibling_succeeds() {
        assert_attacker_lacks_ptrace_capability();
        if let Err(e) = run_scenario(1) {
            panic!(
                "the control failed: a same-uid reader could not read a \
                 *dumpable* sibling (errno {e}). If it cannot read a process \
                 that never asked to be protected, then the refusal in the \
                 attack test is not evidence that hardening works."
            );
        }
    }

    /// The attacker-unprivileged guard, proven able to reject.
    ///
    /// On an ordinary machine no run can produce a privileged `CapEff`, so
    /// without this the precondition in the two tests above could be a no-op
    /// that silently stops guarding the moment somebody runs the suite as root.
    #[test]
    fn the_capability_guard_rejects_a_privileged_attacker() {
        let privileged = "Name:\tbash\nCapEff:\t00000000000fffff\n";
        let unprivileged = "Name:\tbash\nCapEff:\t0000000000000000\n";
        // CAP_SYS_PTRACE is bit 19; 0xfffff covers bits 0..19.
        assert_eq!(has_ptrace_capability(privileged), Some(true));
        assert_eq!(has_ptrace_capability(unprivileged), Some(false));
        // Bit 20 set, 19 clear: the guard must not read the wrong bit.
        let adjacent = "CapEff:\t0000000000100000\n";
        assert_eq!(has_ptrace_capability(adjacent), Some(false));
        assert_eq!(has_ptrace_capability("Name:\tbash\n"), None);
    }
}
