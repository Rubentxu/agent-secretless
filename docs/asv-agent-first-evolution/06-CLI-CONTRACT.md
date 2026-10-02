# Contrato CLI agent-first v1

## 1. Entrada canónica

```bash
asv agent discover --json
```

No necesita argumentos de contexto ni una sesión previa.

## 2. Envelope

```json
{
  "schema": "asv.agent/v1",
  "product_version": "0.XX.Y",
  "protocol_version": 2,
  "status": "ready",
  "data": {},
  "links": [],
  "warnings": []
}
```

### `status`

Valores iniciales propuestos:

- `ready`
- `degraded`
- `blocked`
- `error`

No crear docenas de estados en v1.

## 3. Error

```json
{
  "schema": "asv.agent/v1",
  "product_version": "0.XX.Y",
  "protocol_version": 2,
  "status": "blocked",
  "data": null,
  "error": {
    "code": "SETUP_REQUIRED",
    "message": "Broker service is not configured"
  },
  "links": [
    {
      "rel": "asv://rels/setup",
      "operation": "system.setup",
      "invoke": {
        "program": "asv",
        "argv": ["setup", "--json"]
      },
      "safety": "local-configuration",
      "requires_human": false
    }
  ],
  "warnings": []
}
```

`message` es para humanos. `code` y `rel` son el contrato programable.

## 4. Link

```json
{
  "rel": "asv://rels/doctor",
  "operation": "system.doctor",
  "invoke": {
    "program": "asv",
    "argv": ["doctor", "--json"]
  },
  "safety": "read-only",
  "requires_human": false,
  "description": "Inspect installation and broker health"
}
```

### Reglas

- `program` debe ser un nombre/ruta esperada y no una cadena shell.
- `argv` es un array literal.
- no hay `env` secreto en el descriptor;
- no hay placeholders con material secreto;
- argumentos aportados por el usuario se anexan como elementos, no como interpolación textual.

## 5. Relaciones v1

Núcleo mínimo:

```text
asv://rels/status
asv://rels/doctor
asv://rels/setup
asv://rels/capabilities
asv://rels/credentials/list
asv://rels/session/run
```

Relaciones adicionales sólo si la implementación real está operativa:

```text
asv://rels/github/issue/read
asv://rels/github/issue/create
asv://rels/github/release/create
asv://rels/postgres/connect
asv://rels/postgres/query
asv://rels/ssh/sign
asv://rels/approval/status
asv://rels/audit/read
```

No publicar `approval/request` o `audit/read` si el transporte seguro requerido sigue incompleto.

## 6. Discover — ejemplo healthy

```json
{
  "schema": "asv.agent/v1",
  "product_version": "0.26.0",
  "protocol_version": 2,
  "status": "ready",
  "data": {
    "broker": {
      "reachable": true,
      "compatible": true
    },
    "capabilities": [
      "system.health",
      "session.run",
      "credentials.metadata"
    ]
  },
  "links": [
    {
      "rel": "asv://rels/doctor",
      "operation": "system.doctor",
      "invoke": {"program": "asv", "argv": ["doctor", "--json"]},
      "safety": "read-only",
      "requires_human": false
    },
    {
      "rel": "asv://rels/session/run",
      "operation": "session.run",
      "invoke": {"program": "asv", "argv": ["run", "--"]},
      "safety": "bounded-execution",
      "requires_human": false
    }
  ],
  "warnings": []
}
```

## 7. `doctor --json`

Ejemplo:

```json
{
  "schema": "asv.agent/v1",
  "status": "degraded",
  "data": {
    "cli_version": "0.26.0",
    "broker_version": "0.26.0",
    "protocol_compatible": true,
    "socket": {
      "reachable": true
    },
    "hardening": {
      "dumpable_disabled": true,
      "landlock": "available",
      "seccomp": "available"
    },
    "installation": {
      "channel": "stable",
      "managed_by": "direct"
    }
  },
  "warnings": [
    {
      "code": "TPM_UNAVAILABLE",
      "message": "Hardware TPM capability is unavailable"
    }
  ],
  "links": []
}
```

Un warning de capability opcional no convierte automáticamente el sistema en inseguro. La severidad debe depender de la operación solicitada.

## 8. Capabilities frente a policy

No devolver:

```json
{"allowed": true}
```

si sólo sabemos que la operación existe.

Preferir:

```json
{
  "capability": "github.issue.create",
  "available": true,
  "authorization": "evaluated_on_request"
}
```

## 9. Compatibilidad de schema

- `asv.agent/v1` permite añadir campos opcionales.
- renombrar/eliminar campos obligatorios requiere `v2`.
- una skill que sólo soporta v1 detiene ejecución ante v2 desconocido.
- `protocol_version` IPC y `schema` agent-facing son conceptos distintos.

## 10. CLI humana

Los mismos datos pueden renderizarse en tabla/texto sin cambiar la semántica.

Ejemplo:

```text
Agent Secretless 0.26.0
Broker       healthy
Protocol     compatible
Installation direct

Available:
  session.run
  credentials.metadata
```

La salida humana no es API. La salida `--json` sí.
