# Agent Secretless Vault (ASV)

[![verify](https://github.com/rubentxu/agent-secretless/actions/workflows/verify.yml/badge.svg)](https://github.com/rubentxu/agent-secretless/actions/workflows/verify.yml)

Un plano de control de credenciales local que permite a un agente de IA **usar
una identidad sin que nunca se le entregue el material de la credencial**.

El agente sigue haciendo lo que ya hace: `git push`, `ssh`, `gh`, `curl`. ASV
autentica en nombre del agente, fuera del proceso del agente. El agente nunca
llega a sostener una clave el tiempo suficiente como para que se filtre.

```text
agente ──(sustituto / socket)──▶ broker ──(credencial real)──▶ remoto
        sin material secreto              único poseedor
```

> **Estado: preparación RC pre-1.0 (M13 + gates R2/R3/R5/R6 completados).**
>
> El workspace compila con **719 tests en verde** (`--release`, flakes
> canónicos excluidos; el conteo lo vuelve a derivar el gate `R11 README test count`
> en cada corrida de CI, así que esta línea ya no puede quedarse vieja). El vault, la firma SSH, el brokering HTTP/PostgreSQL,
> la política, el framework OAuth2, el sellado TPM y la recuperación ante
> crashes existen y están testeados. Pendiente antes de un 1.0 que el
> mantenedor aún no ha aprobado: artefactos reproducibles firmados (R0),
> pasada de certificación completa (R11) y el dashboard de operador (M5).
> `agent-secretless-vault-spec/docs/15-ROADMAP.md` es la autoridad de
> planificación.

## Por qué existe esto

Si le das acceso a shell a un agente de IA, cada credencial de la máquina está
a un `env`, un `~/.git-credentials` o una lectura del historial de shell de
distancia. ASV elimina esa clase de fuga: el agente pide al broker que ejecute
la operación sensible, el broker retiene la credencial, el agente recibe el
resultado — nunca el material.

## La invariante

**La API orientada al agente no tiene forma de leer un secreto.** Ni
`getSecret`, ni `exportSecret`, ni ningún alias que lo reproduzca (ADR-0001).
No es una convención que un contribuidor pueda romper silenciosamente; la
imposición es del sistema de tipos:

| Imposición | Dónde | Cómo se demuestra |
|---|---|---|
| `SecretBytes` no tiene `Clone` ni `Serialize`, y su `Debug` imprime solo `SecretBytes(<redacted>)` | `crates/domain/src/secret.rs` | ningún call-site puede clonar o serializar un secreto, y un `{:?}` perdido en un log es seguro por construcción |
| Las peticiones IPC son un enum cerrado sin variante que transporte secretos | `crates/ipc-protocol/src/lib.rs` | cada nombre de método prohibido falla en el decodificador, antes de que un handler lo vea |
| La identidad viene del kernel, nunca del peer | `crates/identity/src/lib.rs` | un cliente que miente sobre su propio uid sigue siendo reportado con veracidad por `SO_PEERCRED` |
| Las fuentes de producción de broker/conectores nunca llaman a `std::env::var*` | `crates/broker/tests/uat_017_env_scan.rs` | un escáner de fuentes rompe el build si reaparece una lectura de entorno con forma de credencial (regla D9) |

## Qué hace hoy

- **Vault local cifrado** — envelope Argon2id + XChaCha20-Poly1305, formato
  versionado, cabeceras autenticadas, ficheros owner-only. Backup/restore bajo
  una passphrase de recuperación *separada*. **Rekey** de passphrase que
  re-envuelve la misma clave de datos, de modo que los backups previos a la
  rotación siguen funcionando (`crates/vault`).
- **Daemon broker** (`asv-brokerd`) — IPC por socket Unix (protocolo v2),
  identidad `SO_PEERCRED`, política Cedar con **deny-by-default**, arranque
  fail-closed: abre `--vault`/`--passphrase-file` al arrancar o niega toda
  operación brokered. Los core dumps se desactivan con `RLIMIT_CORE=0` antes
  de que exista cualquier secreto.
- **Conectores** — GitHub (HTTP, autoridad semántica), PostgreSQL (lógica de
  decisión completa; transporte real pendiente), SSH (el agente pide
  *firmas*, nunca la clave privada).
- **Framework OAuth2 client-credentials** para emisión de sustitutos de corta
  vida (prototipo, M11).
- **Prototipo de sellado TPM** — política de PCR y blob de recuperación offline
  (M12; `SoftwareTpm` es un placeholder, aún no hay camino de hardware real).
- **Recuperación ante crashes** — journal append-only con prefijos de longitud
  y CRC32; una escritura rasgada se detecta y se replay-ea o descarta, nunca
  se aplica a medias (M13).
- **Cuarentena de entorno** — `asv run` limpia las variables con credenciales
  del entorno del agente antes de arrancar la carga de trabajo.

## Qué NO hace (todavía)

Dicho sin adornos, porque un proyecto de seguridad que se sobrevende a sí
mismo no vale nada:

- **Sin dashboard de operador.** La UI Tauri 2 es M5, sin empezar.
- **`LiveConnectorFactory::postgres` devuelve un cliente real**, no
  `UnsupportedInThisBuild`. La variante del enum sigue existiendo, pero es el
  *default del trait* en `crates/broker/src/lib.rs:191`; el override de
  producción está en `:257`. UAT-033 corre contra un PostgreSQL real en CI.
  *(Esta línea decía lo contrario durante varios milestones: leía el default
  del trait y lo reportaba como comportamiento de producción.)*
- **El perfil de hardening M7 es opt-in, no está desconectado.**
  `harden::install_with` se llama desde `crates/broker/src/main.rs:195` tras
  `--harden`; el broker se envía solo con `RLIMIT_CORE=0` cuando no se pasa.
  *(Antes decía que no estaba cableado al binario, y era falso.)*
- **No se usa un uid dedicado para el broker.** El broker corre como tú, así
  que un proceso con tu uid puede leerle la memoria; sólo se interponen
  `PR_SET_DUMPABLE=0` y Landlock. Un uid aparte (M7) es lo que hace que esa
  negación sea incondicional.
- **Sin artefactos firmados todavía (R0).** El tooling de build reproducible y
  firma (cosign/sigstore) es el siguiente gate.
- **El soporte TPM es un prototipo.** `SoftwareTpm` suplanta al hardware; no
  lo consideres ligado a hardware.
- **Lecturas de memoria del mismo uid tienen éxito.** Un proceso corriendo
  como tu usuario puede leer la memoria del broker, porque el broker corre
  como tú. Solo un uid dedicado para el broker (M7) hace la denegación
  incondicional.
- **El 1.0 no ha sido declarado.** El mantenedor lo puerta explícitamente; la
  iteración continúa por debajo de 1.0.

## Inicio rápido

```bash
cargo build --release -p asv-broker
cargo test --workspace --release -- --test-threads=1 \
    --skip uat_028 --skip one_hundred_brokered_reads
# esperado: passed=692 failed=0 ignored=1
```

Prueba el broker con un vault:

```bash
SOCK="$HOME/.asv/broker.sock"
PASS=/tmp/vault.pass   # fichero de passphrase; fuera del historial de shell

# crea un vault (head -c lee /dev/urandom: ningún secreto en el historial)
head -c 24 /dev/urandom | base64 | tr -d '\n' > "$PASS"
asv-vault-tool create --vault /tmp/vault.asv --passphrase "$(cat "$PASS")" --fast

# arranca el broker: configuración por argv, passphrase por fichero (regla D9:
# el código de producción de broker/conectores nunca lee el entorno buscando secretos)
asv-brokerd "$SOCK" --vault /tmp/vault.asv --passphrase-file "$PASS" &

asv --socket "$SOCK" status
```

El broker liga su socket `0600` dentro de un directorio `0700` y **se niega a
arrancar si el socket ya existe**, de modo que no puede secuestrar ni
pisar una instancia en marcha. Si solo se pasa una de `--vault` /
`--passphrase-file`, sale en vez de arrancar medio configurado.

## Estructura del workspace

```text
crates/
  domain/         tipos core, SecretBytes, canonicalización de Authority
  ipc-protocol/   request/response versionado y acotado por longitud (protocolo v2)
  identity/       identidad de carga de trabajo SO_PEERCRED + pidfd
  vault/          envelope cifrado, backup/restore, rekey, prototipo TPM
  policy/         integración Cedar, decisiones deny-by-default
  broker/         manejo de peticiones, sesiones, recovery, daemon asv-brokerd
  cli/            el binario asv: un plano de control, nunca un lector de secretos
  connector-http/ conector GitHub con binding semántico de autoridad
  connector-pg/   conector PostgreSQL (lógica de decisión completa)
  ssh-agent/      servicio de firmas: la clave nunca sale del broker
  ebpfd/          investigación eBPF / separación de privilegios (M8/M9)
tools/
  check-gates.py  audita el mapa de gates UAT -> milestone del spec pack
```

## Verificación honesta

Un tooling de seguridad que no puede fallar es peor que no tener tooling,
porque compra una confianza que no se ha ganado. Este repositorio está
construido alrededor de esa idea.

**Se demuestra que el harness puede fallar.**
`tests/adversarial/test_falsifiability.py` inyecta tres fugas reales en el
código, recompila y exige que el harness rechace cada una. Cada sonda lleva
una auto-comprobación que planta un canary en el vector exacto que escanea y
exige que la sonda lo encuentre; una sonda incapaz de detectar su propio
canary reporta `INVALID` en vez de pasar en vacío.

**Las invariantes estructurales se escanean, no se confían.** UAT-017 recorre
las fuentes de broker y conectores y rompe el build ante cualquier
`env::var*` con forma de credencial — cazó exactamente esa regresión durante
el cableado del vault en R5, y el arreglo (flags argv en vez de variables de
entorno) es el diseño que se ha enviado.

**Existen migration tests porque el formato lo exige.** El gate R2 lista
"migration tests"; `crates/vault/tests/uat_036_rekey_migration.rs` fija el
contrato del rekey de passphrase: la passphrase vieja muere, la nueva abre,
los backups previos a la rotación siguen restaurando, y una passphrase
actual equivocada escribe cero bytes.

Ejecuta todo:

```bash
cargo clippy --workspace --all-targets
cargo test --workspace --release -- --test-threads=1
python3 tests/adversarial/run_harness.py            # 11 sondas + auto-checks
python3 tests/adversarial/test_falsifiability.py    # el harness puede fallar
python3 tools/check-gates.py                        # auditoría del mapa de gates
```

**Esto se comprueba en CI, no solo en local.** Poner los mismos gates en
GitHub Actions encontró inmediatamente dos defectos que toda ejecución local
había pasado por alto. Un proyecto de seguridad que solo la máquina de su
autor puede romper no está verificado.

## Historial reciente de hitos

| Hito | Alcance | Evidencia |
|---|---|---|
| M11 ✅ | Prototipo del framework OAuth2 client-credentials | tag `m11-oauth2-framework` |
| M12 ✅ | Prototipo de sellado TPM + blob de recuperación | tag `m12-tpm-vault` |
| M13 ✅ | Journal de crash/recovery, baseline de auditoría, SBOM, manual de ops | tag `m13-rc-stabilization` |
| R3 ✅ | Chequeo de fuga zero-live-pin en sesiones (UAT-030) | `3e5c42c` |
| R5 ✅ | Vault cableado al binario del broker, fail-closed | `e2a6f65` |
| R6/R11 ✅ | Evidencia de fuzz: 2×30s, ~460k execs, 0 crashes | `8d3a7b5` |
| R2 ✅ | Rekey de passphrase + migration tests, core dumps desactivados | `dba2e73`, `82e08fd` |

Pendiente hacia un 1.0 (aprobado por el mantenedor): **R0** artefactos
reproducibles firmados, **R11** certificación final, dashboard M5, transporte
PostgreSQL real.

## La postura de seguridad se declara, nunca se implica

Cada integración declara una de estas posturas: `STRONG_SECRETLESS`,
`SHORT_LIVED_EXPOSURE`, `ISOLATED_PROCESS_EXPOSURE`, `RAW_PROCESS_EXPOSURE` o
`UNSUPPORTED` (ADR-0014). Un shim de compatibilidad nunca se etiqueta como
equivalente a firmar o hacer proxy, porque así es como "secretless" se
convierte silenciosamente en una mentira.

## Especificación

`agent-secretless-vault-spec/` contiene el pack completo: 20 documentos, 15
ADRs y un manifiesto `SHA256SUMS` (verificado intacto). Se importa
literalmente y no se edita in situ.

## Seguridad

Por favor, no reportes vulnerabilidades en issues públicas. Consulta
[SECURITY.md](SECURITY.md) para saber qué cuenta como vulnerabilidad aquí,
qué es una limitación conocida del milestone actual y cómo comprobar una
frontera por ti mismo.

## Licencia

MIT. Ver [LICENSE](LICENSE).

El pack de especificación bajo `agent-secretless-vault-spec/` se incluye bajo
los mismos términos.

---

📚 **Readme in English / Leerlo en inglés:** [README.md](README.md)
