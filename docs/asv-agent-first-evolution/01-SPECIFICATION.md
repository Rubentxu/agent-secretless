# Especificación — Agent-first Distribution & Discoverable CLI

## 1. Objetivo

Hacer que ASV sea sencillo de instalar, operar y descubrir tanto por humanos como por agentes, preservando la separación de confianza existente y evitando que la skill se convierta en una segunda implementación de la lógica del producto.

## 2. Principios

### P1 — Una sola puerta pública

El contrato de usuario es `asv`. El usuario no necesita conocer `asv-brokerd`, rutas del socket, detalles de systemd ni herramientas internas.

### P2 — Dos procesos cuando la seguridad lo requiere

La simplicidad de UX no implica fusionar procesos. El broker mantiene memoria, permisos y hardening separados de la CLI.

### P3 — Skills fuera del binario

Las skills son conocimiento operacional versionado y distribuido mediante `Rubentxu/agent-skill`. ASV sólo publica una superficie estable y autodescubrible.

### P4 — HATEOAS semántico, no shell textual

ASV devuelve relaciones y descriptores de invocación estructurados. Nunca devuelve una cadena para `sh -c` que el agente deba concatenar o interpretar.

### P5 — La política sigue en el broker

Que una acción aparezca como disponible significa que existe y puede solicitarse; **no** significa que vaya a ser autorizada. Cedar, identidad, sesión y human gates siguen decidiendo en el broker.

### P6 — Progressive disclosure

La skill raíz carga sólo el material necesario para la intención actual. No introduce TPM, PostgreSQL, recovery o GUI cuando la tarea sólo requiere ejecutar GitHub de forma secretless.

## 3. Alcance funcional

### FR-001 — Manifiesto explícito de producto

Debe existir una fuente única de verdad para los componentes distribuibles.

Clasificación inicial:

| Componente | Clase | Distribución normal |
|---|---|---|
| `asv` | public-cli | sí |
| `asv-brokerd` | private-runtime | sí |
| `asv-console` | optional-ui | opcional/separada |
| `asv-vault-tool` | test-harness | no |

El pipeline de release no debe inferir componentes mediante globbing sobre `target/release`.

### FR-002 — Layout de instalación

Instalación de usuario recomendada:

```text
~/.local/bin/asv
~/.local/libexec/asv/asv-brokerd
~/.config/systemd/user/asv-brokerd.service
```

Instalación de sistema equivalente:

```text
/usr/bin/asv
/usr/libexec/asv/asv-brokerd
/usr/lib/systemd/user/asv-brokerd.service
```

`asv-brokerd` no debe estar en `$PATH` como comando de uso normal.

### FR-003 — `asv setup`

`asv setup` debe ser idempotente y poder:

- verificar layout y permisos;
- localizar el broker privado de la misma instalación;
- instalar/actualizar el user service cuando proceda;
- arrancar o verificar el broker;
- preparar runtime directories no sensibles;
- detectar si el vault no está inicializado y describir los siguientes pasos;
- terminar con una comprobación equivalente a `doctor`.

No debe crear o imprimir secretos automáticamente.

### FR-004 — `asv doctor`

Debe tener modo humano y `--json`.

Debe comprobar al menos:

- versión CLI;
- versión broker;
- versión de protocolo IPC;
- socket alcanzable;
- layout de instalación;
- propietario/permisos relevantes;
- broker health;
- hardening disponible/activo cuando sea observable;
- capacidades compiladas y disponibles;
- origen de instalación cuando pueda detectarse;
- incompatibilidades de versión;
- condición degradada sin mostrar valores secretos.

### FR-005 — Entry point agent-first

Debe existir:

```bash
asv agent discover --json
```

Este comando es la entrada canónica de cualquier skill o agente.

### FR-006 — Envelope JSON estable

Las respuestas agent-facing deben usar un envelope versionado con:

- `schema`;
- `product_version`;
- `protocol_version`;
- `status`;
- `data`;
- `links`;
- `warnings` cuando proceda;
- `error` estructurado cuando proceda.

### FR-007 — Relaciones tipadas

Cada `link` contiene como mínimo:

- `rel`: URI semántica estable, p. ej. `asv://rels/doctor`;
- `operation`: identificador tipado estable;
- `invoke`: descriptor argv seguro, no string shell;
- `safety`: clasificación de automatización;
- `requires_human`: booleano;
- `description`: texto breve no normativo.

### FR-008 — Capabilities

`discover` debe exponer capacidades observadas, no deseos del roadmap.

Ejemplo de familias:

- `system.health`;
- `session.run`;
- `credentials.metadata`;
- `github.issue.read`;
- `github.issue.create`;
- `github.release.create`;
- `postgres.connect`;
- `postgres.query`;
- `ssh.sign`;
- `approval.request` sólo cuando realmente exista una ruta segura;
- `audit.read` sólo cuando exista transporte autorizado.

Una capacidad incompleta no debe anunciarse como operativa.

### FR-009 — Machine-readable en comandos clave

Como mínimo, v1 debe incorporar `--json` a:

- `status`;
- `doctor`;
- `credentials`/listado de metadata;
- `agent discover`;
- operaciones que se necesiten como nodos de navegación durante los AAT.

No es requisito convertir toda la CLI en el primer incremento.

### FR-010 — Human-friendly por defecto

Sin `--json`, la CLI mantiene salida legible para humanos. La evolución no debe degradar el uso interactivo.

### FR-011 — Errores navegables

Un error agent-facing debe ofrecer código estable y, cuando exista recuperación segura, relaciones siguientes.

Ejemplos:

- `BROKER_UNAVAILABLE` -> `asv://rels/doctor`;
- `SETUP_REQUIRED` -> `asv://rels/setup`;
- `APPROVAL_REQUIRED` -> relación de estado/solicitud sólo si la ruta segura está implementada;
- `CAPABILITY_UNAVAILABLE` -> `asv://rels/capabilities`;
- `PROTOCOL_MISMATCH` -> `asv://rels/doctor`.

### FR-012 — Skill oficial

Se añadirá `skills/agent-secretless/` en `Rubentxu/agent-skill` con:

- `SKILL.md` router breve;
- `README.md` opcional conforme a las convenciones actuales del repo;
- `references/` segregadas por intención;
- `tests/skill-evals.md`;
- ninguna dependencia de ficheros de otra skill.

### FR-013 — Skill guiada por runtime

La skill no debe codificar una secuencia fija de comandos cuando ASV pueda anunciar el siguiente paso. Debe:

1. ejecutar `asv agent discover --json`;
2. identificar una relación compatible con la intención;
3. ejecutar el descriptor `invoke` sin shell intermedio;
4. interpretar la siguiente respuesta;
5. detenerse ante human gates, estados no soportados o relaciones ausentes.

### FR-014 — Instalación de skill

Debe verificarse al menos:

```bash
npx skills add Rubentxu/agent-skill --list
npx skills add Rubentxu/agent-skill --skill agent-secretless --agent opencode
```

La indexación en skills.sh se verifica aparte: publicar en GitHub no equivale a estar indexado.

## 4. Requisitos de seguridad

### SR-001 — No secret material

Ninguna respuesta del agent API, link, error, doctor o skill puede contener:

- credential values;
- tokens reales;
- private keys;
- passphrases;
- passwords;
- material que permita reconstruirlos.

### SR-002 — No `sh -c`

Los `invoke` se expresan como `program` + `argv[]`. Un consumidor no debe concatenarlos para ejecutar una shell.

### SR-003 — No auto-approval

`requires_human=true` obliga al agente a detenerse o informar. La skill nunca convierte una aprobación en un paso automático.

### SR-004 — No policy replication

La skill no decide permisos. No contiene reglas Cedar ni lógica equivalente.

### SR-005 — Fail closed en incompatibilidad

Si la skill no entiende el `schema` o la CLI no entiende el protocolo del broker, la navegación se detiene con diagnóstico explícito.

### SR-006 — Sin herramientas de harness en release

El paquete normal debe fallar su gate si contiene `asv-vault-tool`, fuzzers, fixtures o binarios no declarados.

### SR-007 — No inferir capabilities por documentación

El runtime sólo anuncia lo que puede probar/servir en la instalación actual.

## 5. Requisitos de mantenibilidad

- El vocabulario de `rel` debe tener representación tipada en Rust.
- Los links deben generarse desde una única capa, no manualmente en cada `println!`.
- El JSON debe tener golden/contract tests.
- Cada relación declarada debe ser alcanzable desde producción o estar marcada experimental/no-operativa.
- El contrato debe permitir añadir campos sin romper consumidores v1.
- Las skills deben cargarse por intención y mantener `SKILL.md` breve.

## 6. No objetivos

No forman parte de este evolutivo:

- fusionar `asv` y `asv-brokerd`;
- embebido de skills/prompts en el binario;
- crear un servidor HTTP local sólo para imitar REST;
- crear un motor general de workflows;
- añadir nuevos proveedores/connector families;
- completar TPM u OAuth2;
- convertir toda la CLI a JSON en una sola fase;
- hacer que Tauri sea requisito para usar ASV;
- crear MCP como ruta principal.
