# M6 Exploration Report

## Goal of this exploration

Decide whether M6 can be done without a live PostgreSQL daemon and
without changing the broker's `ConnectorFactory` API shape.

## Findings

### F1 — The broker's `ConnectorFactory` is github-shaped

```rust
// crates/broker/src/lib.rs:118
pub trait ConnectorFactory {
    fn github(
        &self,
        audience: Authority,
        secrets: Arc<dyn SecretPort>,
    ) -> Result<GithubClient, GithubError>;
}
```

The trait has exactly one method. Adding PostgreSQL needs either a
second method (`fn postgres`) or a generic dispatch on a tagged
audience. **Decision:** add a second method, because the typed-error
semantics of `GithubError` are different from what PostgreSQL needs
and a single method would either lose information or produce a
sum-error that drags `GithubError` into M6's connector.

This is a small extension: `ConnectorFactory::postgres` with its own
error type, both methods on the same trait. Tests that do not care
about PostgreSQL are unaffected.

### F2 — M4's `GithubClient` is built against a real `fake_origin`

`crates/connector-http/src/fake_origin.rs` is the pattern to copy: a
real in-memory TLS server that answers the way GitHub would, bound to
loopback. For M6, a `fake_pg` of the same shape is straightforward and
removes the need for a live PostgreSQL during CI.

### F3 — The agent-side concern (M6-R2) is the trickiest one

The four surfaces — environment, `/proc/<pid>/environ`,
`/proc/<pid>/cmdline`, files the agent writes — are not in the broker's
control once `psql` runs. The broker's only handle is the moment it
spawns the process (or hands the password via a side channel).

A `tokio::process::Command` that pipes the password on stdin and then
`exec`s `psql` is the right shape, because stdin is not in any of the
four forbidden surfaces after the spawn. The pattern matches what the
HTTP connector already does with TLS: the broker injects the
Authorization header into the request bytes, and the agent never
constructs the header itself.

This makes M6-R2's falsification relatively cheap: the test can fork
`psql` (or a stub that just dumps its environment), check the four
surfaces, and confirm the password is absent. The proof is the
spawning helper, not a complex runtime arrangement.

### F4 — UAT-033 has three conditions; we have five scenarios

UAT-033: *"the password is absent from the environment, the process
tree, the connection string, and any file the client writes; an
unauthorized database or role is denied before authentication
completes; revoking the session tears the connection down."*

Mapping:

| UAT-033 condition            | Spec scenario |
|------------------------------|---------------|
| No client-visible password   | M6-S2         |
| Denial before auth completes | M6-S3         |
| Teardown on revoke           | M6-S4         |

The two extras (M6-S1, M6-S5) come from M6's roadmap scope (connector
trait stabilization, DB resource/action policy), not from UAT-033.
Both are needed to keep the connector compatible with the rest of the
architecture (the broker's policy engine already speaks the
`db_resource`/`db_action` grammar through M3's Cedar adapter).

## What this exploration does not cover

- A live PostgreSQL round trip. The fake connector proves the
  architecture; running against a real `postgres` daemon is an M6.5
  task that adds runtime testing but not architectural coverage.
- TLS to PostgreSQL. Reuses the M4 trust model — pinned certificate,
  authority validation in the connector, no agent control over
  endpoints.
- The dynamic DB credential provider adapter spike. Roadmap calls
  this optional and it is not in M6's exit UAT.

## Conclusion

M6 is implementable as a new crate `asv-connector-pg` with a
fake-origin analogue, an extension to `ConnectorFactory`, and five
falsifiable scenarios in `crates/broker/tests/uat_033_pg.rs`. The
exploration is sufficient to move to Specify.
