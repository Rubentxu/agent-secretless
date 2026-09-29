# M6 Specification

## Scope and source

Sources: M6 roadmap (`agent-secretless-vault-spec/docs/15-ROADMAP.md`),
threat model §7, ADR-0001, access modes §3/§6, UAT-033 in
`14-UAT-ADVERSARIAL.md`.

M6 proves that the secret-broker architecture generalises beyond HTTP and
SSH by adding a PostgreSQL reference connector. The agent runs `psql` and
the broker lends a short-lived credential for the requested database and
role; the credential never enters the agent's environment, process tree,
or any file the agent writes.

The PostgreSQL connector MUST NOT authorise a connection that names an
arbitrary authority. Like the GitHub connector, M6's PostgreSQL connector
MUST be semantic: the broker decides database and role, not the agent.

## ADDED Requirements

### M6-R1 Connector trait is stable across protocol families

The `ConnectorFactory` exposed to the broker MUST dispatch on a tagged
audience so the broker does not grow a separate `fn github_*` /
`fn postgres_*` for every provider. The dispatch MUST happen on a
typed enum, not on the audience string itself.

#### Scenario M6-S1: dispatch by tag, not by string match

- **Given** a broker with the M6 connector factory registered
- **When** a session asks for a PostgreSQL audience
- **Then** the broker routes to the PostgreSQL connector
- **And** an HTTP audience whose URL happens to contain "postgres" does
  not route to the PostgreSQL connector

### M6-R2 Password is absent from every agent-visible surface

When the broker lends a PostgreSQL password to a session, the password
MUST NOT appear in:

- the agent's environment variables,
- the process tree of `psql` (visible via `/proc/<pid>/environ` and
  `/proc/<pid>/cmdline`),
- the connection string the agent constructs,
- any file the agent writes (including `~/.pgpass`).

The broker MAY hold the password in memory and pass it via a side
channel: a Unix-domain connection that hands the password to `psql`
through stdin or via a process-spawning helper that closes the file
descriptors it does not need before `exec`.

#### Scenario M6-S2: psql run leaves no client-visible password

- **Given** an open session with the M6 connector and a registered PG
  credential for `db=asv, user=app`
- **When** the agent runs `psql` via the broker
- **Then** `cat /proc/<psql-pid>/environ` does not contain the password
- **And** `cat /proc/<psql-pid>/cmdline` does not contain the password
- **And** no file under the agent's working directory contains the password

### M6-R3 Authorisation denies before authentication completes

An agent that requests a database or role that the policy does not
authorise MUST be denied without ever opening a network connection to
PostgreSQL. The denial path MUST NOT leak whether the database exists.

#### Scenario M6-S3: unauthorised database or role denied before auth

- **Given** a session authorised for `db=asv, user=app`
- **When** the agent asks for `db=other, user=app`
- **Then** the broker returns `Denied` without contacting PostgreSQL
- **And** the response does not reveal whether `db=other` exists

### M6-R4 Connection teardown on revoke

When the broker revokes the session (or the surrogate is revoked), the
PostgreSQL connection MUST be torn down within the time the policy
declares. No further statements succeed.

#### Scenario M6-S4: revoke tears the connection down

- **Given** an open `psql` session through the broker
- **When** the broker revokes the session
- **Then** the next statement from `psql` returns an error
- **And** the underlying TCP connection is closed

### M6-R5 Resource and action policy matches the connector surface

A Cedar policy MUST be able to authorise or deny PostgreSQL actions
without modifying the connector code. The connector surfaces a
`db_resource` and `db_action` whose names match the policy grammar
established for HTTP and SSH.

#### Scenario M6-S5: policy controls which db_action is allowed

- **Given** a Cedar policy that allows `connect` but not `create_table`
- **When** the agent issues `psql -c "create table x (id int)"`
- **Then** the broker denies the statement
- **And** the broker still serves a subsequent `select 1`

## Verification

This milestone's exit is UAT-033, which states three conditions:
no client-visible password, denial before auth, teardown on revoke.
The above requirements are the falsifiable decomposition of those
conditions; each requirement has a scenario the test suite can drive.

## What is deliberately out of scope

- Pooling and connection reuse beyond what the connector needs to
  satisfy one psql invocation.
- The dynamic DB credential provider adapter is described as
  "optional spike" in the roadmap and is not part of M6's exit
  criteria.
- TLS to PostgreSQL is required but not novel; the connector
  reuses the trust model from M4.
