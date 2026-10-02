# Roadmap del evolutivo — M13-DX

## Integración propuesta

Añadir a `agent-secretless-vault-spec/docs/15-ROADMAP.md`, dentro de M13, un incremento transversal denominado:

> **M13-DX — Agent-first distribution & discoverability**

No cambia la secuencia M0..M13 ni crea una nueva familia de conectores.

## DX0 — Product boundary explícita

### Objetivo

Dejar de inferir qué se distribuye a partir de lo que Cargo produzca.

### Trabajo

- manifiesto de componentes de producción;
- `asv` required/public;
- `asv-brokerd` required/private;
- `asv-console` optional;
- `asv-vault-tool` forbidden;
- test del contenido final del bundle;
- `asv-brokerd` instalado fuera de PATH.

### Exit

Un release bundle contiene exactamente los componentes declarados y un test negativo demuestra que introducir `asv-vault-tool` hace fallar el gate.

## DX1 — Human bootstrap

### Objetivo

Instalación y diagnóstico sin conocer internals.

### Trabajo

- `asv setup` idempotente;
- `asv doctor`;
- version handshake visible;
- detección de broker privado;
- user service;
- salida humana y JSON para doctor.

### Exit

En un HOME limpio, instalar bundle + `asv setup` + `asv doctor` llega a un estado inequívoco de ready/degraded/blocked.

## DX2 — Hypermedia CLI v1

### Objetivo

Crear la mínima superficie agent-first autodescubrible.

### Trabajo

- ADT de relations;
- envelope `asv.agent/v1`;
- `asv agent discover --json`;
- links para `doctor`, `setup`, `capabilities`, `credentials/list`, `session/run`;
- `--json` en comandos necesarios para completar los AAT;
- errores navegables;
- contract/golden tests.

### Exit

Un agente de prueba que sólo conoce `asv agent discover --json` puede descubrir estado, diagnosticar un broker ausente y llegar a una operación soportada sin comandos hardcodeados adicionales.

## DX3 — Skill oficial

### Objetivo

Publicar conocimiento agentic sin duplicar el runtime.

### Trabajo en `Rubentxu/agent-skill`

- `skills/agent-secretless/SKILL.md`;
- referencias segregadas;
- evals positivos/negativos/ambiguos;
- catálogo root README;
- validación local;
- instalación selectiva con `npx skills add`;
- verificación posterior en skills.sh.

### Exit

La skill se instala selectivamente, activa en tareas secretless y no activa en tareas que requieren manipular secretos directamente.

## DX4 — Distribution channels

### Objetivo

Hacer accesible el producto sin obligar a compilar Rust.

### Trabajo mínimo

- archives Linux firmados/verificados;
- installer fino;
- soporte mise sobre el mismo bundle;
- metadata `installed_via` para doctor.

### Exit

Dos rutas independientes (installer directo y mise) instalan el mismo par `asv` + `asv-brokerd`, y ambos pasan el mismo doctor/AAT.

## Orden obligatorio

```text
DX0
 ↓
DX1
 ↓
DX2
 ↓
DX3
 ↓
DX4
```

DX3 depende de un contrato real, no de una CLI imaginada. Publicar primero la skill obligaría a hardcodear comportamiento que después habría que migrar.

## Qué no bloquearía este evolutivo

- TPM real;
- OAuth2 live;
- GUI completa;
- eBPF no-go/alternativas;
- nuevos connectors.

El trabajo debe poder integrarse independientemente de esas líneas.

## Commits recomendados

Mantener commits atómicos y Conventional Commits. Ejemplo de secuencia lógica:

```text
test(dist): pin production bundle component set
feat(dist): add explicit product component manifest
feat(cli): add setup and doctor model
feat(cli): add agent discovery schema v1
feat(cli): expose typed agent relations
feat(skill): add agent-secretless router skill
feat(dist): add direct installer bundle
feat(dist): add mise installation path
```

No se reclama `done` hasta que el exit test del incremento correspondiente esté verde.
