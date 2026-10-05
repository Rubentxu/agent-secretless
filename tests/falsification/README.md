# Falsification campaigns

A security row is only evidence if it can go red. Each file here is a campaign
that applies one concrete mutation at a time to a real source file, runs the one
row that is supposed to catch it, and restores the file. A mutation that leaves
its row green is not a pass — it is the finding, and it is reported as one.

## The four buckets

Every campaign reports the same four, and they partition the run so the total
cannot look finished by accident:

| bucket | meaning |
|---|---|
| `red` | the row ran and failed — the mutation was caught |
| `compiler-refused` | the mutation does not compile, so nothing was measured |
| `green (SURVIVOR)` | the row ran and passed — **this is the finding** |
| `measured nothing` | cargo matched no test, or the snippet was not unique |

`measured nothing` exists because of a real failure. An early version of this
harness passed the short test name with `--exact`; cargo matched nothing, printed
`running 0 tests` and `test result: ok. 0 passed`, and the harness read that as a
falsification for all twenty-four mutations. A row that never ran is
indistinguishable from a row that passed unless the harness is built so it
cannot say so.

A non-unique snippet is also `measured nothing`, not a skip that costs nothing:
a harness that silently declines to measure is worse than no harness, because
its total still looks like a number.

## Running them

From the repository root, with cargo on `PATH`:

```bash
python3 tests/falsification/sigv4_falsify.py
python3 tests/falsification/sts_falsify.py
python3 tests/falsification/client_falsify.py
python3 tests/falsification/calendar_falsify.py
python3 tests/falsification/port_falsify.py
python3 tests/falsification/identity_falsify.py lib      # and: reader, socket
python3 tests/falsification/r2c3_falsify.py broker      # and: binding, selfreport
```

They need a built workspace (`cargo build --workspace`) and they take a while:
each mutation is a full `cargo test` of a single row. `CARGO_TARGET_DIR` is
inherited from the environment, so pointing it at a shared target directory
makes the six campaigns markedly faster.

**They rewrite real source files.** Do not edit anything under `crates/` while
one is running — the campaign restores what it changed from a backup it took at
the start, so a concurrent edit is lost. This is the same rule the full suite
has: no source edits while a campaign or a suite is in flight.

## What each one covers

| file | target | mutations |
|---|---|---|
| `sigv4_falsify.py` | `crates/broker/src/aws/sigv4/mod.rs` | 25 |
| `sts_falsify.py` | `crates/broker/src/aws/sts.rs` | 25 |
| `client_falsify.py` | `crates/broker/src/aws/client.rs` | 13 |
| `calendar_falsify.py` | `crates/broker/src/aws/calendar.rs` | 14 |
| `port_falsify.py` | `crates/broker/src/aws/port.rs` | 13 |
| `identity_falsify.py` | `crates/broker/src/aws/identity.rs` | 14, in three passes |
| `r2c3_falsify.py` | `lib.rs`, `aws_binding.rs`, `selfreport.rs` | 9, in three passes |

`sts_falsify.py` is also the base harness the others import, which is why its
mutation list is a module-level `MUTATIONS` that callers replace. That has a
sharp edge recorded in `15-ROADMAP.md`: the base harness reads the list out of
its *own* module namespace, so assigning a same-named list locally does nothing
and a campaign will happily falsify the wrong file while reporting success. Each
harness therefore names its target file in the first line of its own output.

## Known survivors

Two, both recorded in `15-ROADMAP.md` and both kept rather than deleted — a
deleted survivor hides that a branch has no row.

- The post-read size bound in `client_falsify.py`, unexercised because the fake
  origin always declares a `content-length`.
- Printing the port from `AwsBinding`'s `Debug`. It does not leak, because
  `AwsSecretPort` has a hand-written `Debug` that prints the margin and the
  credential ids and nothing else. The defence is two layers down, so the row is
  a regression net and not the evidence.
