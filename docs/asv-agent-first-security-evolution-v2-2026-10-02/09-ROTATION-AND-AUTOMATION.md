# Rotación, migración y workflows durables

> **No-overlap law:** ASV owns rotation semantics and atomic operations. PipelineK owns sequencing/replay/wait/resume for complex rotations. ASV must not grow a hidden durable workflow engine as fallback.

## 1. Por qué PipelineK

Rotar una credencial no es una asignación:

```text
old = new
```

Es un workflow con:

- preparación;
- validación;
- human gates;
- cutover;
- rollback;
- revocación;
- verificación negativa;
- evidencia.

No construir otro workflow engine dentro de ASV.

## 2. Modelo de binding lógico

Consumidores usan:

```text
CredentialBindingRef("github/release")
```

ASV mantiene:

```text
ACTIVE -> cred_A
STAGED -> cred_B
```

Cutover atómico:

```text
ACTIVE A -> B
```

El consumidor nunca cambia su referencia lógica.

## 3. Workflow estándar

```text
PlanRotation
  ↓
IssueCandidate
  ↓
ValidateCandidate
  ↓
ShadowTest
  ↓
Approval?        <- antes de impacto
  ↓
SwitchBinding
  ↓
ValidateLive
  ├─ fail -> RollbackBinding
  └─ pass
       ↓
DrainOldSessions
       ↓
RevokeOld
       ↓
VerifyRevoked
       ↓
SignedReceipt
```

## 4. Idempotencia

Cada operación mutante ASV recibe:

```text
rotation_id
operation_id
idempotency_key
```

Ley:

```text
issue(rot_X, op_Y)
first call -> candidate_B
replay     -> candidate_B
```

Nunca una nueva credencial por replay.

## 5. Reconciliation

Operaciones clasificadas:

```text
plan          reuse
issue         idempotent create
validate      rerun
switch        reconcile
revoke        idempotent/reconcile
verifyRevoked rerun
receipt       reuse
```

PipelineK no debe hacer blind retry sobre efectos inciertos.

## 6. Zero-disruption rotation

Antes de revocar A:

```text
new sessions -> B
old sessions -> drain A
active(A) == 0
then revoke A
```

Policy:

```text
WAIT
DRAIN
REVOKE_NOW
```

## 7. Casos

### API key

```text
issue B → validate → switch → revoke A
```

### PostgreSQL

```text
create credential/role
test
switch
drain sessions
revoke old
negative test
```

### SSH key

```text
generate key broker-side
install public key
test signer
switch logical binding
remove old public key
negative test
```

### Certificate/mTLS

```text
new key broker-side
CSR
CA issue
verify chain
switch
probe
grace/drain
revoke old
OCSP/CRL verification
```

### Federation

No rotar token efímero.

Rotar/verificar:

```text
trust config
issuer
subject mapping
signing keys
audience policy
```

## 8. Adopt/migrate workflow

Ejemplo `.npmrc`:

```text
discover
parse
ingest
create binding
create ASV integration
positive test via ASV
negative test bypass
approval
scrub original
filesystem rescan
receipt
```

## 9. Incident remediation

ASV inmediata:

```text
freeze credential/session
deny new use
```

Luego workflow durable:

```text
collect references
issue replacement
validate
switch
revoke compromised
verify consumers
produce incident receipt
```

## 10. AutomationPort

ASV CLI/control-plane consume:

```rust
trait AutomationPort
```

No el broker data-plane.

`PipelineKAutomation` debe ser opcional. ASV sin PipelineK sigue soportando todas las operaciones atómicas.

## 11. Workflows oficiales

Distribuidos con `pipelinek-asv`, no en el repo de usuario:

```text
credential-adopt
credential-rotate
certificate-rotate
ssh-key-rotate
incident-recover
```

No dejar `.pipeline.kts` como estado/morralla en proyectos.
