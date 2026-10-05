# R2.F — Docker/registry: what secretless posture is actually reachable

Status: research, decided, and two increments implemented. The core lives in
`crates/connector-http/src/registry.rs` and the request loop that spends what
it decides lives in `crates/connector-http/src/registry/client.rs` — not under
the broker, because the `SecretPort` it feeds is defined in that crate and
neither file carries session or policy state.

## The question the mandate asks first

> Primero investigar qué postura fuerte es alcanzable. No introducir un adapter
> que simplemente escriba una contraseña larga en `config.json` y lo llame
> secretless.

So this document exists before any code does, and it exists to be able to say
**no** as well as to say **how**.

## What the protocol actually offers

The OCI / Docker Registry v2 auth flow is a two-party token exchange, and it is
the reason this provider is worth a look at all:

1. The client asks the registry for the resource.
2. The registry answers `401` with a challenge that names where to get a token
   and what is being asked for:

   ```http
   Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:samalba/my-app:pull,push"
   ```

3. The client asks that `realm` for a bearer token, passing `service` and
   `scope`.
4. The token comes back **opaque**, **short-lived** (`expires_in`, and the
   spec says a client should never be handed less than 60 seconds), and it
   carries a `scope` that may be the same as requested **or a subset of it**.
5. The client retries with `Authorization: Bearer <token>`.

Sources: the registry authentication specification
(<https://docs.docker.com/reference/api/registry/auth/>) and the token endpoint
grammar (<https://matsuand.github.io/docs.docker.jp.onthefly/registry/spec/auth/oauth/>).

**The registry never sees a password.** The long-lived credential exists only
between ASV and the `realm`. That is the same shape as the STS work in R2.C and
the same shape as an OAuth2 provider, which is the reason it belongs in M11 and
not in a tools catalogue.

## The posture: STRONG_SECRETLESS, by proxying

Two options were considered and one was rejected.

**Rejected — a credential helper, or anything that writes a token into
`~/.docker/config.json`.** This is the thing the mandate names. A registry
password is long-lived, and `docker login` has no other place to put it. Writing
it to a file the agent reads is exactly "a password in `config.json` called
secretless", and it is worse than the baseline because `config.json` is a file
the agent owns and can copy.

**Chosen — the broker proxies the registry, and the agent never holds a
credential.** The agent runs ordinary `docker` against a loopback endpoint the
broker exposes. The broker:

1. forwards the request to the registry;
2. on `401`, reads the challenge;
3. checks the `realm` against the same address policy every other destination
   goes through;
4. intersects the requested `scope` with what the operator granted;
5. redeems the vault credential at the `realm` for a token with the
   **granted** scope;
6. retries with it.

The agent's position: it holds no registry credential, and it never sees the
token either. The long-lived secret stays in the vault and the token is spent
inside one connection.

This is the same posture the HTTP substitution path already has, which is why
this belongs next to the surrogate machinery rather than in a new subsystem.

## The two properties this provider is genuinely dangerous on

The research is only worth recording if it says where the sharp edges are, and
there are two that no other provider in this repository has in the same shape.

**The `realm` is attacker-supplied input, and following it is server-side
request forgery.** A malicious or compromised registry answers with
`realm="https://127.0.0.1:9000/token"` and the client faithfully goes there —
and the client in that position holds a credential. ASV already has the
mechanism that answers this: `AddressPolicy` with `allow_loopback` off and
`resolve_and_pin`, which is what the connector uses for every other destination.
It is applied here or the posture claim is false.

**The requested `scope` is a request, and it is routinely wider than the
operation.** The registry asks for
`repository:some/repo:delete` when the agent only ever intended a pull, and a
client that forwards the requested scope verbatim hands out a token that can
delete the repository. The scope that reaches the `realm` has to be the
operator's grant, not the challenge's. This is the same rule R2.E settled for
client certificates, arrived at from the other direction.

A third, smaller one worth naming because it will bite the implementation: the
registry's own host and the challenge's `service` are not the same string.
Docker Hub answers on `registry-1.docker.io` and issues its token for
`registry.docker.io`. Any code that assumes `service == host` will get it
wrong for the largest registry in existence, and will get it wrong in a way
that only shows up against production.

## What this does not solve

- **The long-lived credential still exists.** ASV changes who holds it and how
  long the agent has it; it does not make the registry's password short-lived.
  Registries that support OIDC or short-lived CI tokens (GitLab, Harbor, and
  the registry side of GitHub Container Registry) are the cases where the
  underlying secret can also be short-lived, and that is a later increment, not
  this one.
- **A pull from a public repository needs no credential at all**, and the
  specification says so: an anonymous client still receives a token. So the
  reachability check has to be about the `realm` the registry names, not about
  whether the registry is popular.
- **Nothing here touches `docker push` to a local daemon or a build
  context.** Those are R3 adapter territory, not provider territory.

## A third property the research missed, found by writing the rows

The sharp edges above are all about the *host* and the *grant*. The
implementation added a third, and it is the one a reader is most likely to skip
past because it looks like validation rather than security.

A scope reads `repository:<name>:<actions>`. If a repository name may contain a
colon, then a name closes itself early and everything after the colon is read
as **actions**. A repository named

```
app:pull,repository:admin/secret:pull
```

is not a repository with an unusual name. It is a request for two scopes, the
second of which belongs to somebody else, and a client that concatenates
`repository:<name>:pull` around it produces exactly that request. The same
applies to every character the distribution specification's grammar excludes,
and to the length limit, which is what stops a name long enough to be a denial
of service against the token endpoint.

So the grammar is load-bearing rather than decorative: it is what makes `:`
mean one thing. `RepositoryName` has no constructor that skips it, and the row
that pins this is the one that tries the injection rather than the one that
checks a well-formed name.

## What the first increment is, and what it is not

`crates/connector-http/src/registry.rs` parses a `WWW-Authenticate` challenge,
vets the `realm` it names against the same address policy every other
destination goes through, and intersects the requested scope with the granted
one. It is pure parsing and pure refusal: no network, no credential, no vault.
The only lookup it performs is the DNS resolution `resolve_and_pin` already
performs for every other audience, and a `Realm` is a type that cannot be built
without having been through it.

It is not the proxy. It is the part of the proxy that can be wrong in a way a
handshake cannot hide, and it is the part that decides whether a hostile
registry can make this broker send a credential somewhere it must not go.

**Twenty-nine rows, twenty-seven mutations, twenty-seven red.** Two of the
findings were about the tests rather than the code, which is the usual ratio
and the reason the campaign is worth more than the review that preceded it:

- A row that asserted only `is_err()` for each hostile repository name stayed
  green when the trailing-separator refusal became a *different* refusal. Same
  outcome, different reason, and the row could not tell. It now names the reason
  it refused.
- A row using a trailing CRLF as its fixture for the control-character guard
  stayed green with the guard deleted, because the parameter scanner refuses
  `\r` as a malformed parameter name and has nothing to do with the guard. The
  row was green for a reason unrelated to the code it named. It is now split: a
  control character *inside* a value, which does depend on the guard, and a
  separate row that records the CRLF outcome and says which mechanism stops it.

Neither was found by reading the code. Both were found by asking what else could
be holding a green row up.

## R2.F.2, the request loop

`RegistryClient` spends what R2.F.1 decides. The shape of the loop is the
posture in three lines:

1. Ask the registry for the resource, with no credential attached.
2. On a `401`, read the challenge, vet the `realm`, ask the `realm` for a token
   with **this side's** scope, and narrow the grant on the way out.
3. Retry once with the token, and stop.

The stored credential is lent exactly once, by `SecretPort::lend`, to build one
`Basic` header on the token request. It is never a variable anything else can
reach, which is why a mutation that put it on the registry request does not
compile rather than merely failing a test. The token is what the retry carries,
and it is spent inside one connection.

**A row reads the token endpoint's own record of what it was asked for, rather
than the code that built the query.** The query string is the only place the
scope decision becomes visible to a third party, and Docker Hub answers
`pull,push` to a pull, so a client that forwarded the challenge would ask for a
push-capable token while reading an image — with every other check in the loop
still passing.

**Nineteen rows, seventeen mutations, seventeen red.** Two more rows were green
for reasons that were not the code they named:

- The push-body row compared what the fake origin recorded, and the fixture
  reads bodies as text. A mutation re-encoding the body through
  `String::from_utf8_lossy` therefore agreed with the row, because both were
  lossy in the same way. The row now reads the bytes out of the built request,
  where they are still bytes.
- The "no challenge is not a puzzle" row came back green with its
  `BearerChallenge::parse` line replaced, because a `401` with no challenge
  header is refused one line earlier. The mutation was measuring the wrong
  line, and moving it one line up is what turned the row red.

## What is still missing

The loop is not yet reachable from a session. A real request has to arrive from
a brokered session, a `Request` has to name a registry operation, and the broker
has to decide which repository an agent may touch — which means `Action` in the
domain, dispatch in the policy engine, and a verb in the CLI. Those are
R2.F.3, and they are the same three files every remaining roadmap row needs, so
they are the next thing to unblock rather than the next thing to start.

## R2.F.4, the token cache

A pull is dozens of requests — a manifest, a config, a layer per blob — and the
loop as shipped in R2.F.2 redeems a token for each of them. That is not a
connector, it is a load generator aimed at the token endpoint, and it is the
reason the increment had no consumer yet.

So the client keeps the token, and the interesting part is not keeping it. It is
the key:

| field | what leaving it out would allow |
|---|---|
| `action` | a pull's token, found by a push. The endpoint grants `pull,push` to a pull, so this token really can push. |
| `repository` | one repository's token answering for another. |
| `realm` | a token redeemed at one token endpoint presented to another. |
| `credential` | a retired credential outliving its deletion, which is the window `SecretPort::forget` exists to close. |

Two more rules, both about the clock. A token is only handed out with more than
ten seconds left, because a token that expires while the request carrying it is
still being written is a failure with a `401` in it. And a response that says
nothing about how long the token lives is **not cached at all**: guessing a
lifetime for a credential this side cannot watch is how a cache becomes a way
to serve something the provider has withdrawn.

`forget` drops every token derived from one credential and nothing else, and it
is scoped to the credential rather than the session on purpose — the derived
token belongs to the credential, which outlives any session.

**Ten rows, twelve mutations, twelve red.** The finding was the strongest one
of the three campaigns: the key row spelled `TokenKey` out by hand in the test
file and came back green under *all four* of its mutations, because it was
measuring its own hand rather than the constructor `redeem` uses. The key is
built in one place now, `RegistryClient::key_for`, and the row goes through it.
A duplicate spelling of the code under test is a row that passes no matter what
the code does — which is the same lesson as R2.F.1's `is_err()` row and
R2.F.2's text-reading body row, and it is the third time this repository has
paid for it.
