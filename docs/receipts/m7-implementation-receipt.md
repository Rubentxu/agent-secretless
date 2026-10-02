# M7 Implementation Receipt — Linux hardened sessions

## What landed

- `crates/broker/src/harden.rs` — the real seccomp deny-list and Landlock
  ruleset, replacing the M7 probes.
- `crates/ebpfd/` — the privilege-separated helper, a closed eight-verb
  vocabulary with no verb that accepts arbitrary BPF bytecode or a generic
  cgroup write.
- `crates/broker/src/admission.rs` — the three ADR-0015 conditions, written as
  hostile tests: a caller is not the human merely for holding no session.

## Commits

- `7b1eaeb` feat(broker): replace M7 harden probes with real seccomp deny-list and Landlock ruleset
- `afed775` refactor(broker): extract shared worker seccomp deny-list builder
- `851d162` fix(broker): close three HIGH debt findings from the m10 debt gate
- `e59e229` feat(harden): scope the Landlock ruleset to declared paths, not all of $HOME
- `b69c195` chore: bump workspace version to 0.5.0

## Exit UAT

UAT-003 (proc inspection), UAT-023 (cgroup escape), UAT-024 (helper scope) and
UAT-048 (Landlock path scoping).

## Evidence

```
$ cargo test --release -p asv-broker \
    --test uat_003_proc_inspection --test uat_023_cgroup_escape \
    --test uat_024_helper_scope --test uat_048_landlock_install_paths
test result: ok. 3 passed; 0 failed; 1 ignored   (uat_003)
test result: ok. 3 passed; 0 failed               (uat_023)
test result: ok. 9 passed; 0 failed               (uat_024)
test result: ok. 4 passed; 0 failed               (uat_048)
```

`crates/broker/tests/admission_control_plane.rs` carries 11 further hostile
tests on the admission rule itself, each built around a way the "no session
means human" mistake would slip through.

## Known limitations

- **One test is `#[ignore]`d and stays that way here:**
  `uat_003_open_proc_self_mem_returns_eacces_when_undumpable`. It asserts
  `EACCES` from `/proc/self/mem` on an undumpable process, which needs a cgroup
  and kernel configuration this host does not provide. The suite is green
  because the test is declared, not because the property was observed here.
- `crates/ebpfd` is a **structural prototype**: `cgroup_attach_skeleton`
  performs no syscall and returns `Ok(AttachHandle(0))`, and no BPF program
  ships. This is what decided M8 NO-GO, and the reasoning is in the `M8 eBPF
  research gate` row.
- UAT-002 and UAT-016 are proved in `uat_017_env_scan.rs` but carry no header
  claim, because that file is named for UAT-017. Counted in the `UAT claim
  coverage` row.

## Honest observations

- `e59e229` exists because the Landlock ruleset restricted all of `$HOME`
  rather than the operator's declared paths. The M7 exit criterion is about
  scoping, and a ruleset that is broader than the declaration passes a weaker
  test while breaking the property.
- The eBPF helper was kept as a closed-verb surface even though the research
  that would use it did not land. Deleting it would have been the tidier choice
  and the worse one: the vocabulary is what makes the privilege boundary
  inspectable, and M9's TLS bridge still benefits from the pattern.
