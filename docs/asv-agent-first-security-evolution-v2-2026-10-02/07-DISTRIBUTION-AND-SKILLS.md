# Distribución simple y skills agent-first

## 1. Producto visible

El usuario instala Agent Secretless y aprende un comando:

```text
asv
```

Topología:

```text
PUBLIC
  bin/asv

PRIVATE RUNTIME
  libexec/asv/asv-brokerd

OPTIONAL
  asv-console

DEVELOPMENT ONLY
  asv-vault-tool
```

## 2. Regla de packaging

No:

```bash
cp target/release/asv*
```

Sí:

```text
explicit product manifest
+
allowlist
+
artifact content gate
```

## 3. Manifest de producto

Ejemplo conceptual:

```toml
schema = 1

[[component]]
name = "asv"
kind = "public-cli"
required = true

[[component]]
name = "asv-brokerd"
kind = "private-runtime"
required = true
install = "libexec/asv/asv-brokerd"

[[component]]
name = "asv-console"
kind = "optional-desktop"
required = false

[[forbidden]]
name = "asv-vault-tool"
reason = "adversarial harness only"
```

## 4. `asv-vault-tool`

Corto plazo:

- `required-features = ["adversarial-test-tool"]`;
- release allowlist independiente de `--all-features`.

Largo plazo:

- mover herramientas de harness a package/crate de test-support si crecen.

## 5. Instalación

Orden:

```text
P0 archive firmado + installer oficial
P1 mise
P2 deb/rpm
P2 Tauri desktop packages
P3 Homebrew/Nix/AUR según demanda
```

`SDKMAN` no es prioridad natural para el core Rust.

## 6. Setup

```bash
asv setup
asv doctor
```

`setup`:

- idempotente;
- no crea secretos sin decisión del usuario;
- instala/activa broker;
- valida handshake;
- registra mecanismo de instalación;
- permite `--json`.

## 7. Update ownership

`asv` detecta quién gestiona la instalación:

```text
mise
apt
rpm
official installer
```

No pelea con el package manager.

## 8. Supply chain

Release:

```text
artifact
checksums
signature
SBOM
provenance
```

Evolución recomendada:

- metadata estilo TUF para rollback/freeze protection;
- SLSA provenance;
- verificación fail-closed.

No bloquear el primer installer simple hasta diseñar todo el sistema TUF, pero no congelar un updater inseguro como API definitiva.

## 9. Skills

Las skills **no** se compilan dentro de ASV.

Fuente canónica:

```text
Rubentxu/agent-skill/skills/agent-secretless/
```

Estructura recomendada:

```text
agent-secretless/
├── SKILL.md
├── references/
│   ├── setup.md
│   ├── doctor.md
│   ├── operations.md
│   ├── integrations.md
│   ├── approvals.md
│   ├── rotation.md
│   ├── pipelinek.md
│   └── recovery.md
└── evals/
```

## 10. Skill router

La skill raíz:

- identifica intención;
- empieza por `asv agent discover`;
- carga una referencia pequeña;
- sigue `rel`;
- no contiene un grafo hardcodeado completo;
- no conoce secrets;
- no sugiere bypass.

## 11. Compatibilidad skill/product

Publicar:

```text
agent_protocol
broker_protocol
skill_protocol
```

La skill declara un rango soportado.

No distribuirla como bytes dentro del binario; opcionalmente enlazar el bundle compatible desde la release.
