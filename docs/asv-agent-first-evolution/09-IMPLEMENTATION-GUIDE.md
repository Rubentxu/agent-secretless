# Guía de implementación

## 1. Mantener el cambio pequeño

No empezar por la skill. Empezar por una superficie determinista comprobable.

## 2. Cambios propuestos en ASV

### `crates/domain`

Reutilizar tipos existentes de operación donde tenga sentido. Añadir tipos nuevos sólo para conceptos agent-facing que no existan en dominio.

Posibles ADTs:

```rust
pub enum AgentStatus {
    Ready,
    Degraded,
    Blocked,
    Error,
}

pub enum AgentRel {
    Status,
    Doctor,
    Setup,
    Capabilities,
    CredentialList,
    SessionRun,
    // ... sólo operaciones implementadas
}

pub struct AgentInvoke {
    pub program: String,
    pub argv: Vec<String>,
}
```

No introducir `HashMap<String, Value>` como modelo principal si el vocabulario es cerrado.

### `crates/ipc-protocol`

No es necesario convertir el schema agent-facing en protocolo del broker.

La CLI puede componer discovery a partir de:

- versión local;
- handshake/status del broker;
- respuestas IPC existentes;
- capacidades declaradas/observadas.

Sólo ampliar IPC si falta un hecho que el broker sea la única autoridad capaz de conocer.

### `crates/cli`

Separar tres responsabilidades hoy mezcladas alrededor de rendering:

```text
command parsing
      ↓
application result
      ↓
renderer
   ├── human
   └── json-agent
```

No hacer que handlers impriman directamente cada respuesta si se quiere reutilizar el resultado en dos formatos.

Añadir:

```text
asv setup
asv doctor [--json]
asv agent discover --json
```

Y gradualmente `--json` a los comandos requeridos por AAT.

### Módulo sugerido

```text
crates/cli/src/
├── main.rs
├── agent/
│   ├── mod.rs
│   ├── schema.rs
│   ├── relations.rs
│   └── discover.rs
├── doctor.rs
├── setup.rs
└── render/
    ├── human.rs
    └── json.rs
```

No es una obligación de nombres, sino una dirección para evitar inflar `main.rs`.

## 3. Generación de links

Centralizarla:

```rust
impl AgentRel {
    pub fn descriptor(&self) -> AgentLink { ... }
}
```

Luego filtrar según estado/capability.

Evitar esto repetido por handlers:

```rust
json!({"rel": "...", "argv": [...]})
```

porque vuelve a crear vocabulario duplicado.

## 4. Capability derivation

Separar:

```text
compiled capability
runtime reachable
configured
policy authorization
```

Discovery sólo debe afirmar lo que realmente sabe.

Ejemplo conceptual:

```json
{
  "name": "postgres.query",
  "compiled": true,
  "configured": false,
  "authorization": "evaluated_on_request"
}
```

No hace falta exponer todos estos campos en v1 si complican demasiado; pero internamente no colapsarlos en un solo booleano ambiguo.

## 5. Setup y broker privado

`asv setup` debe resolver el broker perteneciente a su propia instalación.

Orden de resolución recomendado:

1. metadata/manifiesto de instalación;
2. ruta relativa conocida desde el ejecutable `asv`;
3. ruta system package conocida;
4. error explícito.

No buscar `asv-brokerd` arbitrariamente en `$PATH` como mecanismo principal.

## 6. Distribution manifest

Crear un test antes de implementación que falle con el bundle actual si contiene componentes no declarados.

El pipeline debe construir explícitamente los targets de producción, por ejemplo conceptualmente:

```text
cargo build --release -p asv-cli --bin asv
cargo build --release -p asv-broker --bin asv-brokerd
```

y copiar únicamente artefactos declarados.

`asv-vault-tool` puede seguir compilándose en tests/harness; no se elimina por este evolutivo.

## 7. Installer

Mantenerlo fino. No meter lógica de seguridad compleja en shell que deba duplicarse con Rust.

Responsabilidades del installer:

- obtener artefacto;
- verificar;
- colocar ficheros;
- invocar `asv setup`.

Responsabilidades de `asv setup`:

- layout runtime;
- servicio;
- health;
- migraciones locales que correspondan.

## 8. Mise

Mise debe instalar el mismo bundle producido por release. No crear otro sistema de packaging.

El test importante es equivalencia de contenido/doctor, no la existencia del plugin/config en sí.

## 9. Skill

Implementar después de DX2.

Integración mínima en `Rubentxu/agent-skill`:

```text
skills/agent-secretless/
  SKILL.md
  README.md
  references/*.md
  tests/skill-evals.md
```

Actualizar README raíz y CI/tests si la colección lo requiere.

## 10. Testing quirúrgico

Durante desarrollo:

- contract tests del nuevo ADT/schema;
- tests del comando afectado;
- test del bundle staging;
- evals de la skill.

En integración/release:

- suite workspace completa;
- adversarial harness;
- distribution AAT/UAT;
- install smoke limpio;
- `agent-skill` validator + evals;
- release gates existentes.

## 11. Observabilidad

No loguear el JSON agent-facing completo si en el futuro pudiera contener metadata sensible. Auditar `operation`, resultado, relation y session refs ya redactados.

## 12. Definición de completado

No considerar el evolutivo cerrado sólo porque exista `asv agent discover`.

Debe demostrarse:

- instalación simple;
- bundle correcto;
- discovery navegable;
- errores recuperables;
- skill instalada;
- eval negativa de secret retrieval;
- falsificación del gate de bundle;
- suite de seguridad sin regresión.
