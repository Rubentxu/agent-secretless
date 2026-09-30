# UAT tooling defects — measured, not inferred

Captured 2026-09-30, after `v0.15.0` shipped, then re-verified the same day
under a second falsification pass. Each entry states the command and the
observed output.

Two claims in the first version of this document were wrong and are
corrected below rather than quietly dropped:

- the plan/report lookup was described as repo-root-relative. It is
  **cwd-relative**, and `uat status` has no `--root` at all.
- `uat plan` was described as having no input that could change its
  output. `--from` exists and is honored; it just never yields features.

## P3 (P1 priority) — plan and report are resolved from the current
working directory, with no fallback

`sddk uat status` resolves `uat-plan-<tag>.yaml` and `uat-report-<tag>.yaml`
relative to the **process cwd**. The XDG storage copy at
`~/.local/share/sddk/projects/p-20a1ee316faf2ba3/uat/` is never consulted.

Falsified in all three directions, so this is not a one-way guess:

```text
# at the repo root, both files present
$ sddk uat status --release v0.15.0 --format json
{"release": "v0.15.0", "plan": "generated", "report": "ready"}

# plan moved away; report still at root; XDG copy of BOTH present
$ mv uat-plan-v0.15.0.yaml /tmp/p.yaml
$ sddk uat status --release v0.15.0 --format json
{"release": "v0.15.0", "plan": "missing", "report": "ready"}

# plan restored, report moved away; XDG copy of the report still present
$ mv /tmp/p.yaml uat-plan-v0.15.0.yaml
$ mv uat-report-v0.15.0.yaml /tmp/r.yaml
$ sddk uat status --release v0.15.0 --format json
{"release": "v0.15.0", "plan": "generated", "report": "not-ready"}
```

In the third probe the XDG report existed for the entire command and still
produced `not-ready`. Neither artifact is read from XDG.

**It is cwd, not the repo root.** Run from a subdirectory the same files are
invisible:

```text
$ cd crates/tls-acceptor
$ sddk uat status --release v0.15.0 --format json
{"release": "v0.15.0", "plan": "missing", "report": "not-ready"}
```

And there is no flag to fix it, because the command does not take one:

```text
$ sddk uat status --release v0.15.0 --root /var/home/rubentxu/Proyectos/rust/agent-secretless
error: unexpected argument '--root' found
$ sddk uat status --help | grep -c root
0
```

So the lookup anchor is the process cwd and nothing else. A monorepo with
crates, or any agent that runs from a crate directory, sees `missing`.

**Blast radius, and a correction to the first version of this section.**
The release precondition is **not** cwd-dependent, because `release` takes
`--root` and resolves through it:

```text
$ cd crates/tls-acceptor
$ sddk release plan --tag v0.15.0 --root <repo> --scope . --cycle <m9>
route: local
branch: main
tag: v0.15.0
head: 3f73a79                      # resolved fine from the subdirectory

$ sddk release apply --tag v0.15.0 --root <repo> --scope . --cycle <m9>
error: cycle ... is not the current release-pending cycle for this project

$ sddk release apply --tag v0.15.0 --root /tmp/nowhere --scope . --cycle <m9>
error: No such file or directory (os error 2)      # bogus root, different error
```

The second error is the good outcome: the precondition passed and the
command advanced to a later check. The third proves the second is not a
masked root failure, since a wrong root fails differently.

**The precondition does not read the report file at all.** This corrects the
first version of this section, which assumed it did:

```text
$ mv uat-report-v0.15.0.yaml /tmp/r.yaml      # report gone from the root
$ cd crates/tls-acceptor
$ sddk release apply --tag v0.15.0 --root <repo> --scope . --cycle <m9>
error: cycle ... is not the current release-pending cycle for this project
```

Same post-precondition error with the report absent, so the gate was
satisfied by the persisted `release-uat-approved` gate receipt, not by
re-reading the YAML. That is also why the original `RELEASE_PRECONDITION`
failure happened before any gate receipt existed: the gate is what the
precondition consults, and back then it had no receipt to consult.

**Cost, still real, but the mechanism was misdescribed.** `sddk release
apply` returned `RELEASE_PRECONDITION: configured local UAT evidence is
missing or failed` while `uat-report-v0.15.0.yaml` sat in XDG with 5/5 PASS,
verdict READY and 0 defects. What actually unblocked it, in the order the
turns happened, was: committing both files at the repo root so `uat status`
could see them, then evaluating the `release-uat-approved` gate with real
evidence. The XDG-only location is what made `uat status` report `missing`,
and that is a real defect; attributing the release failure solely to it was
too simple.

`uat status` should either take a `--root`, or consult XDG storage as a
fallback. Today it has one undocumented location, anchored to cwd.

**Correction: the blast radius is `uat status` alone.** The first version of
this section claimed `uat review` and `uat dashboard` share the bug. That was
an inference from the command names, not a measurement, and it is wrong.
Both take explicit paths, so the caller controls the location and cwd is
irrelevant:

```text
$ cd crates/tls-acceptor
$ sddk uat review --plan <abs>/uat-plan-v0.15.0.yaml --report <abs>/uat-report-v0.15.0.yaml
uat review: release v0.15.0 — 4 items en la Human Review Queue

$ sddk uat dashboard --plan <abs>/uat-plan-v0.15.0.yaml
uat dashboard written: uat-dashboard-v0.15.0.html
```

Both work from a subdirectory. Note that `dashboard` writes its output into
the cwd, which is where the probe left an untracked file that had to be
removed. The bug is confined to commands that infer the artifact path
themselves, and `uat status` is the one that matters.

## P2 (P2 priority) — there is no report schema; reports are parsed as plans

The earlier description said reports are emitted as v2 while the validator
requires v3. That is wrong about the cause, and the version is provably
irrelevant. **No report can pass, at any version**, because the validator
parses a report with the plan schema.

The v2 report fails like this:

```text
$ sddk uat validate --file uat-plan-v0.10.0.yaml
uat validate: OK

$ sddk uat validate --file uat-report-v0.15.0.yaml
error: schema validation failed: line 2 column 10: unexpected event: expected mapping start
 --> uat-report-v0.15.0.yaml:2:10
1 | schema_version: 2
2 | release: v0.15.0
  |          ^ unexpected event: expected mapping start
```

Bumping the version by hand changes nothing, which is the test the first
version of this document was missing:

```text
$ sed 's/^schema_version: 2/schema_version: 3/' uat-report-v0.15.0.yaml > /tmp/r3.yaml
$ sddk uat validate --file /tmp/r3.yaml
error: schema validation failed: line 2 column 10: unexpected event: expected mapping start
```

Identical error, byte for byte, with `schema_version: 3` on line 1. So the
rejection is not a version gate.

Three plan-only requirements, all unsatisfiable for a report:

- a report's `release:` is a scalar, the plan schema wants a mapping with
  `candidate` / `project` / `last_uat_release`. This is the error above.
- a plan's `plain_steps` entries require an `expected` field. Handing the
  validator a plan-shaped document gets `missing field 'expected'`, which
  confirms it is enforcing the plan schema rather than a report schema.
- a report with `features: []` is rejected with
  `plan must have at least one feature with one scenario`, again plan wording
  applied to a report document.

**It dispatches on content, not on filename.** A report renamed to
`uat-plan-*.yaml` still gets the mapping error, and a session renamed to
`uat-plan-*.yaml` gets the plan-features error, so the tool is not
selecting a schema by the `uat-` prefix:

```text
$ cp uat-report-v0.15.0.yaml /tmp/uat-plan-fake.yaml
$ sddk uat validate --file /tmp/uat-plan-fake.yaml
error: line 2 column 10: expected mapping start      # still the report's shape

$ cp uat-session-S-1.yaml /tmp/uat-plan-sess.yaml
$ sddk uat validate --file /tmp/uat-plan-sess.yaml
error: plan must have at least one feature with one scenario
```

A `uat-session` fails the same way a report does, so the session branch is
missing too. The command's own help says it accepts a `uat-plan /
uat-session / uat-report` path, so two of the three documented branches are
unreachable.

**The defect is not confined to `validate`.** `migrate-plan` shares it, which
is what turns "one broken validator" into "no report schema exists":

```text
$ sddk uat migrate-plan --input uat-report-v0.15.0.yaml --output /tmp/mig.yaml
error: invalid plan uat-report-v0.15.0.yaml: error: line 2 column 10: expected mapping start
$ ls /tmp/mig.yaml
ls: cannot access '/tmp/mig.yaml': No such file or directory
```

**The plan side is completely healthy**, which localizes the fault exactly.
Migration works, promotes real content, and the result validates:

```text
$ sddk uat migrate-plan --input uat-plan-v0.15.0.yaml --output /tmp/migp.yaml
uat migrate-plan: /tmp/migp.yaml (1 → 2); features=1, scenarios=5,
                  evidence_promoted=0, risk_promoted=5, timing_promoted=5
$ sddk uat validate --file /tmp/migp.yaml
uat validate: OK
```

So `UatPlan` has a schema, a migration path and a validator, and
`UatReport` / `UatSession` have none of the three. The reports in this repo
are written by the tool and can never be checked by it.

All three reports in this repo fail identically, and no `schema_version: 3`
report exists anywhere in the tree, so there is no working example to
compare against:

```text
uat-report-v0.15.0.yaml -> line 2 column 10: expected mapping start
uat-report-v0.10.0.yaml -> line 2 column 10: expected mapping start
uat-report-v0.7.0.yaml  -> line 2 column 10: expected mapping start
```

## P1 (P2 priority) — `uat plan` emits an empty plan, and accepts any
`--from` without validating it

The command succeeds and writes a file, so it looks like it worked:

```text
$ sddk uat plan --release v0.16.0
uat plan written: uat-plan-v0.16.0.yaml      # exit 0

$ cat uat-plan-v0.16.0.yaml
schema_version: 1
release:
  candidate: v0.16.0
  project: null            <- not inferred, though the repo declares it
  last_uat_release: null   <- not inferred, though v0.15.0 exists
generated_by: uat-planner
generated_at: 2026-09-30T10:33:33Z
features: []               <- 8 lines total, 0 scenarios
```

`--from` exists and is honored, so the first version of this document was
wrong to say the plan has no input. It does change the output:

```text
$ sddk uat plan --release v0.16.0 --from v0.15.0
  last_uat_release: v0.15.0     # populated, so --from is read
features: []                   # still empty
```

So the defect is narrower and more specific than "no inference happens":
`--from` is threaded into the header and never consulted for features, and
`features` is `[]` regardless of input. Measured across five combinations,
including a past release as the candidate:

```text
from=v0.15.0 -> 0 scenarios      from=v0.14.0 -> 0 scenarios
from=v0.1.0  -> 0 scenarios

$ sddk uat plan --release v0.4.0 --from v0.7.0     # a release already in the past
release:
  candidate: v0.4.0
  last_uat_release: v0.7.0
features: []
```

**A second defect in the same flag: no validation of `--from`.** A tag that
does not exist, and a string that is not a tag at all, are both accepted and
echoed back verbatim. Exit codes measured without a pipe, because a
pipeline would report the exit code of the last stage and not of `sddk`:

```text
$ git tag --list v9.9.9            # nothing, the tag does not exist
$ sddk uat plan --release v0.16.0 --from v9.9.9; echo $?
uat plan written: uat-plan-v0.16.0.yaml
0
  last_uat_release: v9.9.9

$ sddk uat plan --release v0.16.0 --from banana; echo $?
uat plan written: uat-plan-v0.16.0.yaml
0
  last_uat_release: banana
```

`rc=0` in all three cases: default, nonexistent tag, and non-tag garbage.

A `--from` pointing at a nonexistent release produces a plan that claims a
baseline it cannot have, and the caller has no signal that it is fiction.
That is the same failure class as this whole document: a tool returning
exit 0 over evidence that does not exist.

Either way, an exit code of 0 with `features: []` is worse than an error: it
hands the caller a valid-looking YAML that is guaranteed to fail the next
step, which is exactly the P2 validator error reached one command later.

`uat plan` either needs to derive features from the given `--from` tag, or
needs to fail loudly when it cannot, and it needs to reject a `--from` that
names no real release.

## Not defects

`cycle next` reporting `no active cycle found` without `--cycle` is a
missing-argument behaviour with a hint, not a bug. The cycle existed and
`cycle status --cycle` read it correctly. Recorded here only because it cost
one wrong conclusion during this session.

`--from` not defaulting to the last UAT'd release despite its documented
default is not counted as a separate defect here, because `features: []` is
already unconditional and would mask it. Fixing the empty-features case
should be measured again before treating the default as broken.

## Coverage of these claims

| claim | how it was established | status |
|---|---|---|
| plan/report read from cwd | 2 commands from 2 directories | falsified in both directions |
| no XDG fallback | XDG copy present during 2 failing probes | reproduced |
| no XDG manifest fallback either | XDG manifest holds 3 entries, all `command_output` from M3, none index a plan or report | reproduced |
| no `--root` on `uat status` | `--help` grep + explicit invocation | reproduced |
| `uat review` / `uat dashboard` also affected | both run from a subdir with explicit paths | **falsified, claim withdrawn** |
| release gate not cwd-dependent | `release plan` and `release apply` from a subdir | reproduced |
| precondition does not read the report file | report removed from root, same post-precondition error | reproduced, corrects first version |
| report cannot validate at any version | v2 and hand-edited v3, identical error | reproduced |
| `migrate-plan` shares the defect | report input rejected, plan input migrates and validates | reproduced |
| plan side is healthy | `migrate-plan` on a plan: 5 scenarios promoted, then `validate: OK` | reproduced |
| dispatch is on content not filename | report and session renamed to `uat-plan-*` | reproduced |
| `uat plan` emits `features: []` | 5 combinations incl. a past release as candidate | reproduced 5x |
| `uat plan` exits 0 on all of them | `$?` read without a pipeline, 3 variants | reproduced 3x |

## Corrections made in this pass

Seven claims across the passes were wrong and are now corrected in place:

1. "repo-root-relative" was wrong; the lookup is cwd-relative and
   `uat status` has no `--root`.
2. "it does not read the repository, the previous tag, or the cycle" was
   wrong; `--from` is read and lands in `last_uat_release`.
3. "the release precondition failed because it could not find the report
   in XDG" was too simple. The precondition consults the persisted
   `release-uat-approved` gate receipt, and with the report deleted from the
   root it still passed. The XDG location is what broke `uat status`, which
   is a real defect, but it was not the sole mechanism.
4. "`uat review` and `uat dashboard` share the cwd bug" was an inference
   from command names, not a measurement. Both take explicit paths and work
   from a subdirectory. Claim withdrawn.
5. "`uat plan` exits 0" was asserted from output text, never measured; the
   earlier pipelines ended in `head`, so `$?` would have been `head`'s exit
   code. Measured without a pipeline: 0 in all three variants, so the
   conclusion held and the evidence for it was invalid.
6. P2 was described as a validator defect. `migrate-plan` shares it, so it
   is better described as a missing report and session schema.
7. "the P2 defect is version-independent" was claimed in the previous pass
   from a v2 report and a hand-edited v3. It held, and is now additionally
   supported by the plan side migrating and validating cleanly.
