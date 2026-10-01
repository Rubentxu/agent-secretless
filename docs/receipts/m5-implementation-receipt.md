# M5 Implementation Receipt — Tauri 2 operator console

## What landed

- `crates/operator-core/` — the console's policy surface with no GUI
  dependency: one capability vocabulary (`Capability::ALL` as the single source
  of truth), exportability policy, clipboard policy and untrusted-text
  handling.
- `apps/desktop/` — the Tauri 2 shell over it. Its own workspace, `gui` off
  by default, strict CSP, no remote origin, and every broker-supplied value
  written with `textContent`.
- `apps/desktop/tests/uat019_probe.c` + `probe-shim.js` — a WebKitGTK probe
  that drives the *shipped* `ui/index.html` and `ui/app.js` against a real
  render engine.

## Commits

- `383b126` feat(desktop): the Tauri 2 shell over the operator core
- `e218d85` feat(operator-core): one vocabulary for console capabilities
- `51e1f2c` test(console): UAT-019 and UAT-020 against a real render engine
- `861a77a` test: the R12 console gate
- `2e6b6f3` test(broker): the M5 console end-to-end flow
- `728e3d1` docs(gates): state M5's row as what was actually verified

## Exit UAT

UAT-019 (hostile label rendered as data, no script execution) and UAT-020
(clipboard policy).

## Evidence

```
$ cargo test --release -p asv-operator-core
test result: ok. 28 passed; 0 failed
```

Machine-asserted in the pipeline: R12's CSP and remote-origin check, and the 28
`asv-operator-core` policy tests, none of which need a GUI toolchain.

**Not machine-asserted in the pipeline:** the WebKit probe. It needs a display
and `webkit2gtk-devel`, neither of which the CI container has, so it runs on
the release host and its result is transcribed into the gate row. Its three
guards each exist because the run without them lied — a control that must
execute, a vacuity check that the front-end actually rendered, and an origin
check.

## Known limitations

- **UAT-019 and UAT-020 cannot be claimed by `check-gates.py`.** The probe is a
  C program and the checker scans Rust only. They are among the eleven
  accounted for in the `UAT claim coverage` row.
- `apps/desktop` is deliberately *not* a member of the root workspace. Were it,
  the pipeline's `cargo build/test/clippy --workspace` would require
  `webkit2gtk-devel` and fail in CI.
- Tauri's own `test` feature is rejected as evidence for UAT-019. Its runtime
  is mocked and never loads a WebView, so it would prove nothing about script
  execution.

## Honest observations

- The probe found a real defect before the console was considered done: the
  front-end compared `exportability` against the string `"HumanOnly"` while
  serde renames the variant to `human_only`. The reveal button was therefore
  never built, and `HumanOnly` rendered identically to `NonExportable`. That is
  the same shape as a test that asserts nothing, and it is why the probe drives
  the shipped files rather than a copy of the render path.
- 2 of the 3 exit criteria are machine-asserted. The gate row says so rather
  than reporting M5 as uniformly green.
