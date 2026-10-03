# Credential Workflow Plane y adapters de tooling

> **Ownership note:** this layer reuses M4 broker/surrogates, M10 isolated compatibility and M11 provider mechanisms. It must not create a second vault, OAuth/STS/mTLS framework, signer or isolated executor.

## 1. Motivación

Muchos tools exigen credenciales mediante configuración local:

```text
npm        ~/.npmrc
Maven      ~/.m2/settings.xml
Gradle     ~/.gradle/gradle.properties
curl       ~/.curlrc / ~/.netrc
Docker     ~/.docker/config.json
Cargo      ~/.cargo/credentials.toml
pip/twine  pip config / ~/.pypirc
NuGet      NuGet.Config
Terraform  provider / registry-specific configuration
```

ASV debe entender estas convenciones sin convertirlas en un nuevo almacén persistente de secretos.

## 2. Operaciones

### Discover

```bash
asv integrations discover --json
```

Detecta:

- tipo de integración;
- fichero;
- owner/mode;
- destinos;
- selectores de credencial;
- presencia de material sensible;
- fingerprint.

Nunca devuelve el valor.

### Plan

```bash
asv integrations plan npm --json
```

Produce estrategias disponibles ordenadas por postura.

### Adopt

```bash
asv integrations adopt ~/.npmrc
```

Importa la credencial al vault de forma segura, crea binding y verifica uso.

### Project

Genera únicamente el contexto efímero mínimo para ejecutar la herramienta.

## 3. Pipeline

```text
discover
   ↓
parse safely
   ↓
IntegrationPlan
   ↓
adopt?
   ↓
CredentialBinding
   ↓
choose strongest strategy
   ↓
ephemeral projection / proxy / signer
   ↓
tool
   ↓
cleanup + receipt
```

## 4. V1 adapters

Prioridad:

1. npm
2. Maven
3. Gradle
4. curl

Después:

5. Git helpers
6. Docker registry
7. Cargo
8. pip/twine
9. NuGet
10. Terraform/provider catalogue

## 5. Parsing seguro

Los adapters **no ejecutan** configuración.

### XML

Para Maven:

- DTD deshabilitado;
- external entities deshabilitadas;
- network resolution deshabilitada;
- límites de tamaño/profundidad.

### Includes

- deny por defecto;
- allow sólo dentro de raíces explícitas;
- symlink canonicalization;
- límite de recursión.

### Ownership

Rechazar o degradar cuando:

- config world-writable;
- owner inesperado;
- symlink no confiable;
- path cambia entre plan y execute.

## 6. Fingerprinting y TOCTOU

```text
discover:
  path
  inode
  owner
  mode
  digest

execute:
  re-check all relevant identity
```

Si cambia:

```text
CONFIG_CHANGED
```

y se obliga a replanificar.

## 7. Binding semántico

```rust
struct CredentialBinding {
    credential_ref: CredentialRef,
    integration: IntegrationKind,
    audience: Authority,
    resource: Option<Resource>,
    operations: Set<Operation>,
    source_selector: Option<Selector>,
}
```

No almacenar sólo:

```text
"npm-token"
```

Sino:

```text
cred X
para registry.npmjs.org
scope @org
operations read/publish
```

## 8. Projections

### Strong secretless

```text
surrogate config
   ↓
ASV proxy
   ↓
real credential
```

### Short-lived exposure

```text
dynamic token
   ↓
ephemeral config
   ↓
tool
```

### Raw process exposure

```text
real static credential
   ↓
ephemeral config
   ↓
tool
```

La tercera sigue siendo `RAW_PROCESS_EXPOSURE` aunque el fichero dure milisegundos.

## 9. Materialización efímera

Preferencias Linux:

- `${XDG_RUNTIME_DIR}/asv/...`;
- `0700` dirs;
- `0600` files;
- tmpfs cuando proceda;
- `O_TMPFILE`/memfd cuando sea compatible;
- unlink temprano;
- cleanup idempotente;
- process isolation cuando el target verá la credencial.

## 10. Scrub del original

Nunca eliminar automáticamente el secreto original sólo porque el import haya terminado.

Secuencia:

```text
import
verify ASV storage
verify new integration
negative test old path
human approval
scrub
rescan
receipt
```

## 11. Agent-first

La skill no enseña cómo modificar `.npmrc`.

Pide a ASV:

```text
discover → plan → adopt/project
```

y sigue los `links`.
