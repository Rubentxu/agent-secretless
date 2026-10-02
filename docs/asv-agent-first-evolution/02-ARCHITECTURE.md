# Arquitectura del evolutivo

## 1. Separación de capas

```text
                  capa indeterminista
┌───────────────────────────────────────────────────┐
│ Agente                                            │
│   + skill agent-secretless                        │
│   - comprende intención                           │
│   - elige una relación anunciada                  │
│   - no posee secretos ni replica Cedar            │
└──────────────────────┬────────────────────────────┘
                       │ argv estructurado / JSON
───────────────────────┼─────────────────────────────
                  frontera determinista
                       │
┌──────────────────────▼────────────────────────────┐
│ asv                                               │
│ - CLI pública                                     │
│ - discovery                                       │
│ - envelope JSON                                   │
│ - setup / doctor                                  │
│ - traduce intención operativa a IPC tipado        │
└──────────────────────┬────────────────────────────┘
                       │ Unix IPC
┌──────────────────────▼────────────────────────────┐
│ asv-brokerd                                       │
│ - identidad                                       │
│ - sesiones                                        │
│ - Cedar                                           │
│ - vault                                           │
│ - secret lending/signing                          │
│ - connectors                                      │
└───────────────────────────────────────────────────┘
```

La skill no es una capa de autorización. Es una capa de navegación.

## 2. Producto frente a distribución

```text
Agent Secretless
├── público
│   └── asv
├── runtime privado
│   └── asv-brokerd
├── opcional
│   └── asv-console
└── development-only
    └── asv-vault-tool
```

La instalación oculta complejidad sin borrar fronteras de confianza.

## 3. Modelo hipermedia para CLI

REST HATEOAS suele devolver recursos y links HTTP. ASV no necesita HTTP para beneficiarse de la misma propiedad.

Equivalencia conceptual:

| REST | ASV CLI |
|---|---|
| recurso | estado/resultado JSON |
| URI | `rel` semántico |
| método | `operation` |
| link | descriptor `invoke` |
| servidor decide links válidos | runtime ASV decide links válidos |
| cliente no concatena rutas | skill no inventa comandos |

Ejemplo:

```json
{
  "schema": "asv.agent/v1",
  "status": "ready",
  "data": {
    "broker": "healthy"
  },
  "links": [
    {
      "rel": "asv://rels/session/run",
      "operation": "session.run",
      "invoke": {
        "program": "asv",
        "argv": ["run", "--"]
      },
      "safety": "bounded-execution",
      "requires_human": false
    }
  ]
}
```

`argv` puede ser un prefijo que requiera argumentos de la intención del usuario. Esos argumentos deben validarse por el parser de ASV; la skill nunca interpola secretos.

## 4. Por qué no crear `asv agent next` ahora

Un `next` stateful convertiría ASV en orquestador y obligaría a modelar workflows completos demasiado pronto.

La versión pequeña conserva HATEOAS mediante una regla más simple:

> cada respuesta agent-facing publica los links actualmente válidos.

Si los AAT posteriores demuestran que el agente necesita reconstruir demasiado estado entre respuestas, entonces se puede introducir un `navigation_context` opaco y `agent next` en un ADR independiente.

## 5. Vocabulario tipado

Representación conceptual:

```rust
enum AgentRel {
    Doctor,
    Setup,
    Capabilities,
    CredentialList,
    SessionRun,
    SessionClose,
    GithubIssueRead,
    GithubIssueCreate,
    GithubReleaseCreate,
    PostgresConnect,
    PostgresQuery,
    SshSign,
    ApprovalStatus,
    AuditRead,
}
```

No todas las variantes se anuncian siempre. La construcción de links depende de estado y capacidades observables.

El `operation` debería compartir vocabulario con los ADTs de dominio/policy cuando sea semánticamente el mismo concepto; no mantener dos catálogos manuales independientes.

## 6. Fuente de verdad de navegación

```text
Domain/Operation ADT
        │
        ├── Policy mapping
        ├── IPC mapping
        └── Agent relation mapping
```

El objetivo es que añadir una operación nueva fuerce a revisar todas las proyecciones relevantes por exhaustividad del compilador.

## 7. Riesgo y human gates

Los links incluyen metadatos de seguridad, pero no sustituyen el control real.

Ejemplo:

```json
{
  "rel": "asv://rels/approval/status",
  "operation": "approval.status",
  "requires_human": true,
  "safety": "human-gate"
}
```

La skill interpreta `requires_human=true` como stop condition. El broker sigue siendo quien impide self-approval.

## 8. Skills como progressive disclosure

Dentro de una única skill inicial:

```text
agent-secretless/
├── SKILL.md                   router mínimo
├── references/
│   ├── 00-decision-tree.md
│   ├── 01-discovery-hypermedia.md
│   ├── 02-install-setup.md
│   ├── 03-execution.md
│   ├── 04-integrations.md
│   ├── 05-approvals-audit.md
│   ├── 06-diagnostics.md
│   └── 07-security-anti-patterns.md
└── tests/
    └── skill-evals.md
```

Esto respeta las convenciones ya utilizadas por `agent-skill`: una skill autocontenida, entrada breve y referencias locales bajo demanda.

## 9. Cuándo dividir la skill

No dividir por anticipado. Dividir en skills independientes sólo si las evaluaciones muestran alguna de estas señales:

- activaciones falsas frecuentes entre operación y administración;
- `SKILL.md` se vuelve demasiado grande pese a referencias;
- agentes cargan sistemáticamente material que no usan;
- los ciclos de versión de administración y uso divergen;
- skills.sh necesita superficies distintas para discovery.

Una partición futura razonable sería `agent-secretless-use`, `agent-secretless-admin` y `agent-secretless-audit`, todas independientes.
