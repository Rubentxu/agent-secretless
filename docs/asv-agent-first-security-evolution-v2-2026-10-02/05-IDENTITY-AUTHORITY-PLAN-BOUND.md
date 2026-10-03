# Identidad, autoridad efímera y ejecución ligada a plan

> **Ownership note:** plan/strategy selection chooses among capabilities already delivered by ASV, especially M11 provider mechanisms. It does not implement a second provider framework.

## 1. Objetivo

Reducir la diferencia entre:

```text
"el agente tiene permiso"
```

y:

```text
"esta operación exacta está autorizada, para este recurso, usando este tool y durante este intervalo"
```

## 2. Identidades separadas

ASV debe mantener conceptos distintos:

```text
PrincipalIdentity   humano/origen
AgentIdentity       actor agentic
WorkloadIdentity    proceso/workload
SessionIdentity     sesión ASV
ToolIdentity        binario/herramienta
TransactionId       intención/transacción
```

No inferir autoridad sólo por nombre de agente.

## 3. Tool identity

Antes de prestar autoridad puede verificarse:

```text
requested command
   ↓
realpath
   ↓
owner
   ↓
inode
   ↓
digest
   ↓
optional package/provenance
```

Un plan puede quedar ligado al digest.

PATH hijacking:

```text
plan: /usr/bin/npm sha256=A
execute: ~/project/bin/npm sha256=B
=> PLAN_INVALIDATED
```

## 4. ActionIntent

Debe ser serializable sin secretos y permitir policy.

Campos recomendados:

```text
transaction
principal
actor
workload
session
operation
resource
destination
tool identity
config fingerprint
intent origin
expiry
```

### Intent origin

```rust
enum IntentOrigin {
    HumanDirect,
    ScheduledWorkflow,
    TrustedTool,
    RetrievedContent,
    UntrustedToolOutput,
    DelegatedAgent,
}
```

Policy ejemplo:

```text
RetrievedContent + production.write
=> require human approval
```

ASV no interpreta el prompt; consume provenance estructurada.

## 5. Plan-bound execution

```text
ActionIntent
   ↓
plan
   ↓
policy
   ↓
authorization
   ↓
plan digest
   ↓
execute
```

El plan digest debe incluir sólo dimensiones deterministas y relevantes.

Si cambia:

- operación;
- recurso;
- destino;
- tool;
- config;
- arguments ligados;
- policy epoch;
- runtime posture requerida;

la autorización se invalida.

## 6. Credential elimination

Antes de buscar un secreto estático:

1. native federation;
2. workload identity;
3. dynamic short-lived credential;
4. proof-of-possession;
5. signer/proxy/helper;
6. surrogate;
7. projection;
8. isolated exposure.

## 7. Proof-of-possession

Cuando un protocolo lo soporte, preferir credenciales sender-constrained.

ASV mantiene la private key broker-side.

```text
stolen token
+
no proof key
=
unusable
```

No prometer DPoP/mTLS donde el proveedor no lo soporte.

## 8. Workload identity

Port:

```rust
trait WorkloadIdentityProvider
```

Adapters futuros:

```text
LocalPidfdIdentity
SpiffeIdentity
TpmAttestedIdentity
ConfidentialWorkloadIdentity
```

La identidad local debe seguir usando kernel evidence/pidfd como base; SPIFFE es un adapter, no un reemplazo obligatorio.

## 9. Delegación atenuada

Multi-agent:

```text
child authority ⊆ parent authority
```

Leyes:

```text
operations_child ⊆ operations_parent
resources_child  ⊆ resources_parent
audience_child   ⊆ audience_parent
ttl_child       <= ttl_parent
uses_child      <= uses_parent
posture_child   >= minimum required
```

No existe privilege amplification por delegación.

## 10. Human approvals

Para operaciones críticas, la aprobación puede ligarse a `plan_digest`.

Futuro:

```text
ActionIntent digest
  ↓
WebAuthn/FIDO challenge
  ↓
signed approval
```

ASV conserva:

- principal;
- authenticator assurance;
- user verification;
- digest aprobado;
- timestamp;
- expiry.

El agente nunca puede autoaprobar.

## 11. Audit receipt

Cada ejecución sensible debe poder producir:

```text
transaction_id
principal
actor
workload
operation
resource
destination
tool_digest
intent_digest
plan_digest
policy_digest/ref
decision
credential_strategy
posture
attestation_ref
observed_effect
timestamp
```

Sin secret material.
