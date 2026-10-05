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
| `k8s_binding_falsify.py` | `crates/broker/src/k8s/binding.rs` | 12, one-for-one against 20 rows |
| `s3_falsify.py` | `crates/broker/src/aws/s3.rs` | 13, one-for-one against 23 rows |
| `s3_object_falsify.py` | `crates/broker/src/aws/s3/object.rs` | 9, against 15 rows |
| `aws_audience_falsify.py` | `crates/broker/src/aws/audience.rs` | 9 red + 1 compiler-refused, against 14 rows |
| `r2b2_falsify.py` | `lib.rs`, `oauth2_binding.rs`, `policy/src/lib.rs`, `selfreport.rs` | 15, in five passes |

`sts_falsify.py` is also the base harness the others import, which is why its
mutation list is a module-level `MUTATIONS` that callers replace. That has a
sharp edge recorded in `15-ROADMAP.md`: the base harness reads the list out of
its *own* module namespace, so assigning a same-named list locally does nothing
and a campaign will happily falsify the wrong file while reporting success. Each
harness therefore names its target file in the first line of its own output.

## Known survivors

Three, all recorded in `15-ROADMAP.md` and all kept rather than deleted — a
deleted survivor hides that a branch has no row.

- The post-read size bound in `client_falsify.py`, unexercised because the fake
  origin always declares a `content-length`.
- Printing the port from `AwsBinding`'s `Debug`. It does not leak, because
  `AwsSecretPort` has a hand-written `Debug` that prints the margin and the
  credential ids and nothing else. The defence is two layers down, so the row is
  a regression net and not the evidence.
- **`r2b2_falsify.py`'s `independence` pass — and this one is a result rather
  than a gap.** It widens `ALLOWED_AUDIENCES` by one host and asserts the OAuth2
  happy path *still passes*, which is the measurement that the generic-IdP
  surface does not depend on the allowlist at all. `Resource::OAuth2Client` is a
  separate type that never reaches `audience_is_approved`, so stretching the list
  cannot reach it in either direction. The design claim is stated here as a
  survivor rather than as a paragraph, which is the only form of it that cannot
  quietly stop being true.

That third survivor is also the sharpest thing this file has to say about
**where a mutation is filed**. The same campaign's first pass aimed the two
*dangerous* widenings at OAuth2 rows, and all three survived — which reads as a
finding and was an artefact. The harm of stretching the list falls on GitHub and
AWS, which share the `Api` resource type, so an OAuth2 row cannot go red however
far it is stretched. Re-aimed at the policy crate's own
`unapproved_audience_is_denied_even_though_it_canonicalizes`, both go red. The
harm is measured and the independence is measured, and they are not the same
measurement; a campaign that reported the first three survivors as a gap in the
test would have been wrong about which arrow to move.

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

`r2b2_falsify.py` is the second campaign to file something wrongly, and it did
so twice, so the pattern is worth having in one place:

- a survivor that was **a missing row** — nothing tested session ownership, and
  the mutation deleting the ownership check passed because the fixture's session
  *was* owned. Adding the row turned it red.
- a **row that could not fail** — one measured UTF-8 strictness on a path where
  the token is always valid UTF-8, and another accepted *any* refusal, which left
  the non-2xx check unfalsifiable because a JSON parse failure is also a refusal.
  A row that cannot go red is worse than no row, because it reads as coverage.
- a `measured nothing` from passing a **bare test name** to a `--exact`
  invocation. The bucket was honest — nothing *was* measured — but the cause was
  the harness's own addressing, and reporting a harness typo as a result about
  the code is how a campaign starts being believed for the wrong reason.

Both times the code was fine and the *evidence* was not. That is the recurring
finding of this file: the falsifier finds defects in the tests more often than in
the code, and the tests are the part that is assumed.

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

`k8s_binding_falsify.py` is 12 mutations against 20 rows, and the account is
shorter than the ones above for a reason worth stating: the mutations take the
rows red **one for one**, with no overlap, so unlike the port and the filter
there is no gap between the mutation count and the row count to explain.

Eight rows are not reached, in three groups.

**Five are positive** — a declared cluster name is accepted, `cluster.local` is
accepted, a public audience without the exception is accepted, a binding serves
the credential it declares, and a check that refused everything would fail. A
declaration module is almost entirely refusals, and that is precisely the shape
in which a `check` returning `Err` unconditionally would look perfect.

**One is held by the type in front of it.** `.svc` cannot be constructed as an
`Authority` at all, so the row about a bare suffix is really a row about
`Authority`, and the suffix check in this module is not what saves us. Knowing
*which layer* closes a case is the difference between a check you can reason
about and one you are relying on by luck.

**Two ride on a derived `Debug`** for the exception field, which no single edit
here changes. The row about the *binding's* own `Debug` is different and is
filed, because `finish_non_exhaustive` is a line — and replacing it with a plain
`finish` is four characters that silently widen what a `{:?}` of a live binding
reveals.

Most of these mutations are attempts to widen one exception, and the exception
is the reason this module exists. Kubernetes is the only provider here whose
correct audience is normally a **private** address: `kubernetes.default.svc`
resolves to a ClusterIP, and `AddressPolicy` refuses private addresses because
that is where cloud metadata services live. So the unavoidable exception has to
be made narrow: an IP literal cannot declare itself in-cluster, the check is
anchored to the end of the name rather than a fragment of it, and an exception
on a public audience is refused as the sign of a config nobody read.

Two of the rows here were vacuous before this campaign and are worth naming,
because both would have passed forever:

`the_projected_token_path_is_the_one_kubernetes_actually_uses` read its path out
of a fixture in the test file, so it was pinning its own test and would have
stayed green through any change to the shipped path. The constant now lives in
the product and the row compares it against the documented string.

`K8sBinding::new` constructed its own client, and constructing a client performs
the DNS pin — so the binding could not be built in a row at all, and `serves`,
the one method that decides which cluster a request reaches, had no coverage.
It now takes the client, the same split `AwsBinding::new` already uses.

`s3_falsify.py` is 13 mutations against 23 rows, 13 red one for one, and the
module it falsifies exists to hold one property: **the path that is signed is
the path that is sent.** The type has a single `path` field, so there is no
second one to drift; two of the mutations try to break it anyway, one by
re-encoding the canonical form and one by rebuilding it from the parts. Neither
is easy to write against this shape, which is the point of the shape — an
implementation with two path fields would have exactly the second one in it, and
the signature would be computed over one resource while the request fetched
another. AWS reports that as a credentials error, not an encoding one.

Ten rows are not reached. Four test `encode_component`, which lives in `sigv4`
and has its own campaign of sixteen rows against AWS's published vectors —
re-filing them here would measure the same code twice and go stale the day
`sigv4` changed. Three are the other half of a rule whose mutation is filed
elsewhere. Two are positive, and one is the path-style `match` arm.

**The campaign found two defects, and they are not symmetric, which is the
interesting part.**

The bucket validator had an explicit `is_ascii_uppercase` arm with its own
message. Filing the mutation that deletes it produced a survivor — the catch-all
below already refuses `Acme` — so the arm was redundant and is gone.

The underscore arm survived the same treatment and **stayed**. Removing it does
not change whether `acme_artifacts` is refused, because `_` is outside the
catch-all's set. What it changes is the message: the row asserts the refusal
names the rule, and the catch-all does not mention underscores. A check that
earns its keep through the diagnosis rather than through the effect is still
load-bearing, and a campaign that had reported it as redundant would have been
wrong.

Two other findings are about the campaign rather than the code, and both are the
kind the harness exists to make impossible to miss:

The first pass filed a mutation against deleted code, because the arm it named
had just been removed. The second pass produced two survivors that were
**artifacts of mine** — I edited the isolated checkout while the campaign was
running against it, which invalidated both the measurement and the file the
campaign restored. A third pass on an untouched copy gave 13 red and no
survivors. The rule is already in the harness contract in this file's own
header; it is repeated here because it was learned by breaking it.

And the harness docstring predicted sixteen rows red, on the argument that three
mutations would each take a second row for the other half of their rule. They
do not — the harness credits one row per mutation, and a second attribution
would be a claim nothing checked. The number in the file is the one that was
measured.

`s3_object_falsify.py` is 9 mutations against 15 rows, and six of the rows are
unreachable by design rather than by omission. Two of them are the module's
whole claim: `no_field_of_the_answer_can_hold_the_object` and
`the_response_type_has_nowhere_to_put_a_body` are destructuring rows, so adding
a field that could carry the object breaks the crate instead of failing an
assertion. That is the strongest form this repository has for a "there is
nowhere for it to go" property, and the campaign cannot turn it red — which is
the point, not a gap.

**This module does not read the response body, and that is forced rather than
chosen.** S3 answers a failure with an XML `<Error>` document, and this
workspace has no XML parser by decision: a parser brings a DTD, a DTD is an
XXE surface, and `aws::sts` says so at the top of its own file. So the status
line is the signal, the body is discarded unread, and the refusal says so —
because an operator who sees a bare `403` goes looking for an IAM decision that
is not there. The mutation that reads a body is possible to write and is the
most damaging edit available in the file, because it would smuggle a parser
past a decision made deliberately.

**The campaign found a real log-injection hole.** `ObjectResponse::header`
returned the *first* matching value. The row checking an optional header for a
control character came back green under an injected second
`x-amz-version-id` — because the first, clean one is what a lookup returns. A
duplicated header is exactly the injection vector, and the reader was blind to
the half of it that carries the payload. It is now `values`, returning every
match, and `header` refuses a duplicate outright rather than resolving it by
arrival order — two `content-length` values are two answers to "how big is it",
and picking one would make the answer depend on the order the origin happened to
serialise them in.

Two more findings are about filing rather than about code, and both are the kind
a harness exists to surface.

`the_response_type_has_nowhere_to_put_a_body` was first written as two
`ObjectResponse` values, one "with a body" and one without, asserting they read
the same. It cannot be written that way — the type has no body field, so the
fixtures differed in their headers and the row failed for an unrelated reason.
The claim was true and the row was measuring something else.

And the mutation for `is_populated` had its direction backwards. The row
asserts an empty object is *not* populated, so making the method always return
`false` satisfies it perfectly and reports a survivor that means nothing. A
property like that is two-sided and each side needs its own mutation; the other
side was already covered by the happy-path row, and the pair now pins the method
from both ends.

`aws_audience_falsify.py` closes half of an open item R2.C has been carrying
since its own vertical ran, and the half it closes is the one with an attack in
it.

`AwsDeployment` carried a `region` and an `audience` as two independent fields.
The credential scope is built from one and the request goes to the other, and
AWS accepts that — the global endpoint routes by the region in the signature —
which is exactly what makes it dangerous: the operator believes they pinned
something, and what they pinned is not tied to what they sign for. The property
is now that a deployment signs for a region and talks to **that region's**
endpoint or the global one, as two shapes and nothing else.

The comparison is anchored to a whole label, and the rows that hold it are hosts
that contain the right characters. `mysts.s3.us-east-1.amazonaws.com` is a
bucket name in the host, because S3's virtual-hosted addressing puts one there
and a bucket is something anyone can create. `evil-sts.eu-west-1.amazonaws.com`
ends with the region and the AWS suffix, so anything looking at the end of the
name rather than the start approves it. A `contains("sts.")` check passes the
first; an `ends_with` on the prefix passes the second.

The one mutation to read twice is the **order**. Validating the region's shape
*before* comparing it is what stops a region string carrying a dot from turning
a whole-label match into a substring one. Flipping it leaves every other row in
the campaign green, because every other row configures a well-shaped region.

**The campaign found one defect in this module and one row it could not reach,
and the first draft of its own docstring had both counts wrong.**

Removing the "at least two parts" rule from the region validator left every
answer unchanged — the character set and the digit rule were carrying it — so
the arm is gone. That is the same finding as the bucket validator's
`is_ascii_uppercase` arm in `s3_falsify.py`, and the shape repeats: a check that
never changes an answer is a second way to say something.

The S3-bucket row stayed green under the substring mutation, for a *second*
reason. The substring split produces `s3.us-east-1` as the region, and the
single-label rule refuses it before anything else looks. The same mutation
against the `evil-sts` row does go red, because there it yields a clean
`eu-west-1`. So the row is genuinely uncovered and the mutation is genuinely
caught — one row per mutation is the harness's design, and filing the same
mutation against both would be an attribution nothing checked.

**What this does not do.** Whether a regional endpoint is *approved* is the
policy crate's question, and `asv_policy::audience_is_approved` still lists only
the global endpoint. That half needs the region passed alongside the audience and
is a change to that function's contract, so it is not made here. A deployment
pinned to a regional endpoint will load, sign correctly for its region, and then
be refused by policy. That is the correct order: the refusal is loud, and it is
the policy crate's decision rather than something a broker should widen quietly.
