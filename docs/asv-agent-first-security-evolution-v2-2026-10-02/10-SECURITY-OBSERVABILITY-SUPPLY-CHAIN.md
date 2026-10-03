# Seguridad transversal, observabilidad y supply chain

## 1. Receipts firmables

El audit chain actual puede evolucionar a receipts portables:

```text
AuthorizationReceipt
RotationReceipt
AdoptionReceipt
IncidentReceipt
AttestationReceipt
```

Todos secret-free.

## 2. Decision vs observed effect

Registrar ambos:

```text
policy decision
observed effect
```

Si:

```text
decision = DENY
effect = happened
```

crear invariant violation de severidad crítica.

## 3. OTLP

Exportar sólo metadata segura:

```text
agent.id
session.id
transaction.id
operation
resource_ref
tool.digest
decision
posture
latency
outcome
```

No exportar por defecto:

```text
raw prompt
raw tool args
Authorization header
credential value
secret-bearing config
```

## 4. MCP

MCP es adapter del mismo catálogo de capabilities.

```text
ASV domain capability catalog
      ↙          ↘
     CLI         MCP
```

No implementar dos authorities.

No exponer tools:

```text
get_secret
show_token
export_credential
```

## 5. Agent runtime enforcement

ASV puede integrarse con middleware/control hooks de runtimes agentic.

Objetivo:

```text
agent tool call
  ↓
ASV enforcement point
  ↓
identity/policy/credential
```

No requiere acoplarse a un framework concreto en domain.

## 6. Landlock/seccomp adaptive posture

Detectar capabilities reales del kernel.

`asv doctor sandbox` proyecta:

```text
filesystem restrictions
network restrictions
unix socket restrictions
seccomp
cgroup
ptrace posture
```

No inferir sólo por número de versión.

## 7. Supply chain del propio ASV

Distribución debe evolucionar hacia:

- artefactos reproducibles;
- SBOM;
- provenance;
- signature;
- anti-rollback/freeze metadata;
- exact product identity;
- verificación fail-closed.

## 8. Tool trust

Opcionalmente incorporar:

```text
digest
fs-verity
IMA
package signature
fapolicyd posture
```

como evidencia.

## 9. Security events

Eventos:

```text
attestation_failed
destination_violation
policy_denied
credential_replay
session_escape
tool_identity_changed
plan_invalidated
unexpected_effect
```

Respuesta local inmediata permanece en ASV.

Orquestación externa:

```text
OTLP/webhook/syslog
  ↓
Ansible / SIEM / workflow
```

ASV no debe convertirse en Ansible.

## 10. Fail-closed contracts

- unknown operation: deny;
- unknown strategy: unsupported;
- stale plan: deny/replan;
- stale attestation: deny si policy la exige;
- unknown config mutation: invalidate;
- failed cleanup: visible security failure;
- partial rotation: reconcile, nunca asumir éxito.
