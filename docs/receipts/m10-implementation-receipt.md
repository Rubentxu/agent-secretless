# M10 Implementation Receipt — Isolated exec compatibility

## What landed

- `crates/broker/src/isolated_exec.rs` — the isolated worker runtime:
  registered templates only, separate identity and namespaces, Landlock and
  seccomp, egress enforcement, and secret injection that reaches the child
  only.
- The `ISOLATED_PROCESS_EXPOSURE` posture label, which is the honest
  description of what this milestone produces and the input R10's row reads.

## Commits

- `fe5ace4` feat(broker): add isolated worker runtime
- `e861e98` docs(broker): correct the stated validation site of the seccomp profile
- `851d162` fix(broker): close three HIGH debt findings from the m10 debt gate
- `afed775` refactor(broker): extract shared worker seccomp deny-list builder

## Exit UAT

UAT-021 (isolated worker egress), UAT-022 (transformed stdout leak) and
UAT-040 (runtime denied rather than downgraded).

## Evidence

```
$ cargo test --release -p asv-broker \
    --test uat_021_isolated_worker_egress \
    --test uat_022_transformed_stdout_leak \
    --test uat_040_isolated_worker_runtime
test result: ok.  5 passed; 0 failed
test result: ok.  7 passed; 0 failed
test result: ok. 15 passed; 0 failed
```

UAT-040 is the one that matters most for this milestone's actual claim: the
runtime must *deny* an unregistered program rather than quietly run it
unisolated, and `uat_040_allow_policy_is_refused_not_downgraded` is the test
that says so.

## Known limitations

- **UAT-040 was written ahead of the spec.** Its header originally read "Not a
  normative UAT: `14-UAT-ADVERSARIAL.md` defines UAT-001..UAT-034 and UAT-040
  is not among them." It is now defined in `14`, owned by M10, and the header
  records that decision rather than being quietly rewritten. What was
  provisional was the number, never the property.
- The worker is Linux-specific. The isolated-exec compatibility claim is
  scoped to the cgroup v2, Landlock and seccomp version this milestone
  targeted.
- `R10 compatibility truthfulness` is still `partial`: the posture label
  exists, but the per-integration catalog M11 requires has no live provider to
  populate.

## Honest observations

- `e861e98` corrects a comment that named the wrong validation site for the
  seccomp profile. A doc that points a reader at the wrong line is worse than
  no doc, and this one had been carried for several milestones.
- The three HIGH findings in `851d162` came from a debt gate aimed at this
  milestone specifically. The milestone was not closed by the existence of its
  code; it was closed after the gate found things.
