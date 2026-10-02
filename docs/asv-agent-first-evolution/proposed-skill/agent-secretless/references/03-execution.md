# Ejecución secretless

## Objetivo

Permitir que la herramienta objetivo trabaje sin recibir el secreto real.

## Flujo

1. `asv agent discover --json`.
2. Seleccionar una relación de ejecución compatible.
3. Ejecutar el `invoke` anunciado.
4. Mantener argumentos del comando objetivo como argv, no shell textual.
5. Observar status/error/links resultantes.

## `asv run`

Cuando `session.run` sea la relación anunciada, conserva la semántica:

```text
asv run -- <program> <arg1> <arg2> ...
```

No insertes tokens, passwords o private keys en esos argumentos.

## Evidencia

Reporta como mínimo:

- capability/operation usada;
- resultado;
- si hubo degraded posture;
- si existe human gate pendiente.
