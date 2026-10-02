---
name: agent-secretless
description: "Opera Agent Secretless Vault (ASV) sin exponer credenciales: descubre capacidades reales mediante la CLI agent-facing, ejecuta trabajo secretless, diagnostica instalación/sesiones y respeta human gates. Úsala cuando un agente necesite Git/SSH/GitHub/PostgreSQL u otras operaciones soportadas por ASV sin recibir el secreto, o cuando haya que instalar, comprobar o diagnosticar ASV."
metadata:
  version: "0.1.0"
  asv-agent-schema: "1"
---

# Agent Secretless — router agent-first

ASV es la autoridad determinista. Esta skill **navega** el producto; no reimplementa vault, policy ni workflows.

> Entrada canónica: `asv agent discover --json`.

## Modos

| Modo | Cuándo | Referencia |
|---|---|---|
| `discover` | saber si ASV está disponible y qué puede hacer | `references/01-discovery-hypermedia.md` |
| `setup` | instalar/bootstrap, broker ausente, instalación legacy | `references/02-install-setup.md` |
| `execute` | ejecutar trabajo protegido por ASV | `references/03-execution.md`, y sólo si hace falta `04-integrations.md` |
| `diagnose` | error, schema/protocol mismatch, estado degraded/blocked | `references/06-diagnostics.md` |
| `operator` | approvals/audit/metadata con intervención humana | `references/05-approvals-audit.md` |

Si la intención es ambigua, empieza por `discover`. Carga `00-decision-tree.md` sólo cuando necesites decidir el modo.

## Reglas no negociables

1. No pidas, leas, exportes, imprimas ni copies material secreto.
2. No inspecciones el vault, `/proc`, environment, argv o logs para recuperar credenciales.
3. No inventes un comando ASV cuando exista un `link` anunciado por el runtime.
4. Ejecuta `invoke.program` + `invoke.argv` como argv estructurado; no lo conviertas en `sh -c`.
5. Valida `schema`. Si no soportas la versión, detente y diagnostica.
6. Una capability disponible no equivale a autorización. El broker decide.
7. `requires_human=true` es un stop: no autoapruebes ni busques bypass.
8. No ejecutes `asv-brokerd` directamente salvo diagnóstico explícito de desarrollo; para producto usa `asv setup/status/doctor` y los links anunciados.
9. Si ASV no anuncia una operación, no la simules con un secreto obtenido por otra vía.
10. Reporta hechos observados: versión/schema, status, operación, resultado y bloqueo; nunca atribuyas una verificación que no ejecutaste.

## Flujo mínimo

```text
intención
  ↓
asv agent discover --json
  ↓
validar schema/status
  ↓
seleccionar rel compatible
  ↓
ejecutar invoke estructurado
  ↓
leer nueva respuesta
  ├─ success → cerrar/reportar
  ├─ link seguro → continuar
  ├─ requires_human → detener
  └─ error/unknown → diagnose
```

## Definition of Done

- la operación se realizó mediante una capability anunciada por ASV, o quedó explícitamente bloqueada/no soportada;
- el agente nunca recibió secret material;
- no se ejecutaron comandos ASV inventados para sortear una relación ausente;
- cualquier human gate quedó en manos humanas;
- el resultado incluye evidencia suficiente para distinguir success, blocked, degraded y unsupported.
