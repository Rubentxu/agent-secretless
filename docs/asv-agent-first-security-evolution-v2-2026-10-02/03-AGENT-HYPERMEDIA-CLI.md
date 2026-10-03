# CLI agent-first y navegación hipermedia

## 1. Objetivo

El agente debe poder empezar con una única operación conocida:

```bash
asv agent discover --json
```

y seguir únicamente affordances devueltas por ASV.

Las skills enseñan el protocolo de navegación; ASV publica el grafo efectivo.

## 2. Principio

```text
Skill = cómo navegar
ASV   = qué caminos existen ahora
```

No mantener el workflow completo en Markdown.

## 3. Envelope

```json
{
  "schema": "asv.agent/v1",
  "state": "ready",
  "links": [
    {
      "rel": "asv://rels/capabilities",
      "invoke": {
        "program": "asv",
        "argv": ["agent", "capabilities", "--json"]
      }
    }
  ]
}
```

### Reglas

- `invoke.program` + `argv[]`, nunca shell serializado.
- Todos los IDs sensibles son opacos.
- Ninguna respuesta contiene secreto.
- Los `rel` son estables y versionados.
- Errores devuelven rutas de recuperación.
- Si no existe affordance, el agente no debe inventarla.

## 4. Comandos mínimos

```text
asv agent discover --json
asv agent capabilities --json
asv agent describe <operation> --json
asv agent plan ... --json
asv agent execute --plan <id> --json
asv doctor --json
```

No hace falta implementar todos simultáneamente. `discover`, `capabilities` y `doctor` forman el primer slice.

## 5. Rel vocabulary inicial

```text
asv://rels/setup
asv://rels/doctor
asv://rels/capabilities
asv://rels/describe-operation
asv://rels/plan
asv://rels/execute
asv://rels/request-approval
asv://rels/approval-status
asv://rels/audit
asv://rels/integration-discover
asv://rels/integration-plan
asv://rels/integration-adopt
asv://rels/rotation-plan
asv://rels/rotation-start
```

## 6. Errores navegables

Ejemplo:

```json
{
  "status": "blocked",
  "code": "APPROVAL_REQUIRED",
  "approval_ref": "apr_...",
  "links": [
    {
      "rel": "asv://rels/approval-status",
      "invoke": {
        "program": "asv",
        "argv": ["approvals", "status", "apr_...", "--json"]
      }
    }
  ]
}
```

Otro:

```json
{
  "status": "error",
  "code": "BROKER_NOT_READY",
  "links": [
    {
      "rel": "asv://rels/doctor",
      "invoke": {
        "program": "asv",
        "argv": ["doctor", "--json"]
      }
    }
  ]
}
```

## 7. Progressive disclosure

El agente que necesita GitHub no recibe contexto de PostgreSQL/TPM/eBPF.

```text
discover
  ↓
operation family
  ↓
specific operation
  ↓
required next action
```

## 8. `asv doctor`

Debe convertirse en contrato estable de soporte y agent self-recovery.

Salida deseada:

```json
{
  "healthy": true,
  "version": "0.x.y",
  "broker": {
    "reachable": true,
    "protocol": 7
  },
  "security": {
    "landlock": true,
    "seccomp": true,
    "tpm": false,
    "attestation": "unsupported"
  },
  "distribution": {
    "installed_via": "mise"
  }
}
```

No incluir rutas o metadata que expongan secretos.

## 9. HATEOAS y policy

El grafo publicado debe ser:

```text
product capabilities
  ∩
policy
  ∩
session
  ∩
integration availability
  ∩
runtime posture
```

No un catálogo estático.

## 10. Compatibilidad de protocolo

```text
ASV version        0.x
agent protocol     1
broker protocol    N
skills protocol    1
```

Las skills declaran:

```text
supports agent protocol >=1 <2
```

No se versionan por igualdad exacta con el binario.
