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
python3 tests/falsification/k8s_request_falsify.py       # the Kubernetes request core
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
| `k8s_request_falsify.py` | `crates/broker/src/k8s/request.rs` | 24 |
| `k8s_port_falsify.py` | `crates/broker/src/k8s/port.rs` | 8, taking 9 of its 15 rows red |
| `k8s_client_falsify.py` | `crates/broker/src/k8s/client.rs` | 11, against 17 rows |
| `k8s_metadata_falsify.py` | `crates/broker/src/k8s/metadata.rs` | 7 red + 2 compiler-refused, against 13 rows |

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

`k8s_request_falsify.py` has **none**, and that is a result rather than an
absence of trying: 24 mutations, all red, none refused by the compiler, none
measured nothing. Writing it found two things that were removed from the module
rather than kept — an `ApiError` arm nothing could construct, and three
traversal checks the per-label loop already covered. Both were claims the code
could not keep, and a campaign that had found neither would have left them in
place looking handled.

One mutation here is worth naming because it was **misfiled**, not missing. The
narrowing of `Verb::takes_name` to `Verb::Get` was filed against a row that
still passes under it, and would have been reported as a survivor — which reads
as a gap in the test rather than a gap in the filing. What it actually breaks is
`delete` ceasing to require a name, so that is the row it is filed against now.

## Rows that no single-site mutation can reach

Not every row is falsifiable, and the number that is not is reported rather than
folded into a total that would then read as more coverage than exists.

`k8s_port_falsify.py` files 8 mutations and takes **9** of its module's 15 rows
red. The two numbers differ because one mutation breaks two rules: the empty and
the relative token path are a single condition, so removing it fails both path
rows at once. That was measured rather than argued — applying that mutation on
its own and running the whole module gives `13 passed; 2 failed`. The harness
credits one row per mutation, so it reports the relative row; the empty row is
counted in the total without a second attribution.

The other six rows fall into two groups. Three assert a **structural** fact: the
port has no getter, the constructor reads nothing, and `forget` takes `&self`
over a port that holds no state. No edit to the file undoes any of them —
breaking them needs a mutation that *adds* a method, a read, or a field.

Three are **positive** rows — a well-formed token arriving verbatim, the row
that says a port refusing everything would fail, and the row that says the token
never appears in the port's own rendering. These are the rows that catch the
port being useless rather than leaky, and breaking one needs a *compound*
mutation: a port that lends nothing is not one edit away. Filing a multi-site
edit to force one would measure a rewrite rather than a defect.

Both numbers belong in any summary of the campaign. A total that reported only
the first would be the same overstatement this file exists to prevent.

`k8s_client_falsify.py` files 11 mutations against 17 rows. The other 6 are not
reachable by a single-site edit, and "not covered" without saying *which kind*
is the same overstatement in a different font, so they are grouped.

**Two are positive** — the row that asserts a well-formed get reaches the
origin with its bearer header, and the row that says a client which never sent
anything would fail. A client that stops sending is not one edit away; it needs
the send removed and the returns reworked.

**Two are structural.** `a_client_is_refused_when_the_audience_is_a_private_address`
and `a_client_is_refused_when_the_port_is_zero` re-assert `PinnedClient`'s own
refusals. They are kept because a client that assembled its own transport
instead of borrowing the pinned one would silently lose both, and they would
catch that. No edit *in `client.rs`* can undo them: `assemble` has one call into
the transport and it is the one that checks. Falsifying them belongs to
`transport.rs`, which already has the rows.

**Two need a compound edit**, and both came out of the campaign rather than out
of foresight, so the reasoning is kept.

`a_lend_error_means_no_header_and_no_request` has *two* defences between a
failed `lend` and a socket: the `?` on the call, and the sink's own refusal to
hand over a header it was never fed. The first pass filed the mutation that
removes the `?` against this row and got a survivor — the right measurement and
the wrong conclusion, because removing one of two defences does not break
*whether* a request is sent, it degrades the *diagnosis*: "the token file could
not be read" becomes "the port lent nothing to sign", which is true and useless.
That is a real defect, and
`a_lend_refusal_names_the_cause_rather_than_the_consequence` was added to catch
it.

`no_refusal_this_client_produces_contains_the_token` is a **misfiling that was
corrected rather than dropped**. The mutation filed against it put the
*response body* into the oversized-body refusal, expecting it to repeat the
token. It does not: the token is in the request header and never in the
response, so the row stayed green because the mutation did not do what its label
said. Reaching this row needs a mutation that *adds* a format site for the
token somewhere — a plausible future guard such as "token longer than 4 KiB"
whose message includes the value — plus a row that exercises it. Two sites, so
it is filed as compound rather than counted as a green row.

`k8s_metadata_falsify.py` is the one harness here whose result is not a single
number, because two of its nine mutations are *supposed* to stop the build.

`no_field_of_the_answer_can_hold_the_value` is a destructuring row. The
mutations that would carry a Secret's value — or its key names — into the answer
add a field to `SecretMetadata`, so the crate stops compiling rather than an
assertion failing. That lands in the **compiler-refused** bucket, which is a
stronger answer than a red row and not a weaker one: the type is the guard, and
it fires before the test can run. Reporting those two as survivors would be
reporting the harness missing something it was built to catch.

Both mutations are filed against `SecretMetadata` rather than the private view
on purpose. A field added only to the view compiles, is never read, and changes
nothing an agent can observe — filing there would have produced two more
survivors while proving nothing at all.

So: 13 rows, 7 taken red one-for-one, 2 held by a compile-time guard, and 4
unreached. Of the 4, three are positive rows — an empty Secret still answers, a
Secret with no metadata still answers, and a filter refusing everything would
fail — and the fourth is the base64 row, which the type guard covers and the
campaign cannot.

Three defects in this harness's own first draft are recorded rather than
cleaned away, because all three were caught by the harness refusing to report a
number it had not measured:

Two mutations anchored on a snippet that appears twice in the file, and were
reported as SKIP — "snippet not unique" — rather than silently applied to the
first match. One used `unwrap_or_default()` on a type with no `Default`, and was
reported as compiler-refused rather than as a red row it never earned. And one
was filed against a row it could not reach: a document with no `data` member
goes through serde's `#[serde(default)]` and never enters the map visitor, so
no mutation of the visitor can touch that row. It needed its own, and now has
one — removing the `default`.

The docstring of the harness also claimed the kind-check mutation would take two
rows red. The campaign measured one. A document with no `kind` falls to the
`None` arm, which is still a refusal, so the two arms are the same refusal and
one mutation does not reach the other. The claim was corrected to the number
that was measured.
