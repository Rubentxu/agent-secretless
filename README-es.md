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

> **Estado: pre-1.0, en v0.36.0. Certificado en este árbol por la fila R11; la
> release aún no se ha publicado, y los gates lo dicen.**
>
> El workspace compila y hay **2083 tests enumerados**. Con `cargo test`, 2082
> se ejecutan y pasan y 1 queda fuera de las compilaciones de depuración por
> construcción: el presupuesto de latencia p95 lleva
> `#[cfg_attr(debug_assertions, ignore)]`, porque un presupuesto de latencia
> medido contra ed25519 en depuración es una afirmación sobre
> `debug_assertions`, no sobre el producto. Ese test se afirma con `--release`,
> y por eso la corrida en release de abajo — con los dos filtros `--skip` que
> documenta — ejecuta 2081 de ellos. Medido en el host de certificación sobre
> este árbol, ese presupuesto pasa con **p95=5332us frente a 6000us** — 11% de
> margen, sobre un Xeon E5-2682 v4. Revisiones anteriores de este fichero
> afirmaban 1490us; la cifra nunca se volvió a derivar y la fila había dejado de
> ser una medición. El conteo y la aritmética
> del inicio rápido los vuelve a derivar en cada corrida de CI el gate
> `R11 README test count`, que resta los filtros `--skip` que documenta el propio
> inicio rápido en vez de comprobar una suma, de modo que un bloque que se salta
> un test y luego afirma el conteo completo falla en vez de pasar sobre una
> aritmética que no pudo ocurrir. El vault, la
> firma SSH, los brokers HTTP y PostgreSQL, la política Cedar, la consola de
> operador y el puente TLS sobre CONNECT existen y se ejercitan. El framework
> OAuth2 está **implementado y en uso en producción** contra un authorization
> server **autoalojado** — uno real que habla RFC 6749/7009/7662/8707, no un IdP
> de terceros, y esa diferencia es la mitad de M11 que sigue abierta. El
> sellado TPM sigue siendo un **prototipo** sin camino de producción, porque eso
> necesita hardware que esta máquina no tiene.
>
> **El estado verificable vive en
> [`16-SECURITY-RELEASE-GATES.md`](agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md),
> no en este fichero.** Una tabla de estado en un README es una afirmación que
> nadie comprueba; la que se había quedado vieja estaba aquí, y ahora es una
> tabla en el documento de gates que `scripts/check-gate-status.py` verifica
> contra el repositorio.
> [`15-ROADMAP.md`](agent-secretless-vault-spec/docs/15-ROADMAP.md) es la
> autoridad de planificación, incluida la secuencia de aquí a v1.0.

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
- **Daemon broker** (`asv-brokerd`) — IPC por socket Unix (protocolo v11),
  identidad `SO_PEERCRED`, política Cedar con **deny-by-default**, arranque
  fail-closed: abre `--vault`/`--passphrase-file` al arrancar o niega toda
  operación brokered. Los core dumps se desactivan con `RLIMIT_CORE=0` antes
  de que exista cualquier secreto.
- **Consola de operador** — un plano de control Tauri 2 sobre un web view
  local: sin origen remoto, con CSP estricto y sin forma de que el front-end
  pida el valor de una credencial almacenada. El flujo completo añadir →
  conceder → uso por el agente → revocar está probado contra un proceso de
  broker real en CI. *(Este README dijo durante varios milestones que el
  dashboard estaba "sin empezar" y "pendiente antes del 1.0". Ambas eran
  falsas: M5 se entregó.)*
- **Conectores** — GitHub (HTTP, autoridad semántica), PostgreSQL (lógica de
  decisión completa, más un transporte real probado contra un servidor de
  verdad cuando el pipeline levanta el sustrato), SSH (el agente pide *firmas*,
  nunca la clave privada). `LiveConnectorFactory::postgres` devuelve un cliente
  real, no `UnsupportedInThisBuild`; la variante del enum sigue existiendo,
  pero es el *default del trait* en `crates/broker/src/lib.rs:191` y el
  override de producción está en `:257`. *(Este README antes reportaba el
  default del trait como comportamiento de producción, y decía "transporte
  real pendiente" y "UAT-033 corre contra un PostgreSQL real en CI" en la
  misma frase. La primera era cierta en un `cargo test` local y la segunda
  sólo en el pipeline.)*
- **Puente TLS sobre CONNECT** — CA efímera por sesión, autorización estricta
  del destino, y la credencial real sustituida dentro del túnel mientras el
  cliente solo sostiene un sustituto de un solo uso.
  **No** es una redirección de socket eBPF: ese gate de investigación
  devolvió NO-GO y lo que se entregó fue el camino de proxy explícito.
- **Framework OAuth2 client-credentials** para emisión de sustitutos de corta
  vida — **implementado, y con un consumidor en producción** (M11).
  `asv-brokerd --oauth2-clients PATH` declara las credenciales que este broker
  canjea por tokens de corta vida: el client secret se lee del vault, se gasta
  en un POST HTTPS al token endpoint, y lo que recibe la operación es un access
  token de corta vida emitido por el provider. El secreto se queda en el broker.
  Un scope concedido que difiere del pedido aborta, un token sin `expires_in`
  positivo se rechaza, un token endpoint que no sea HTTPS se rechaza de
  entrada, y un provider que deja de responder detiene la operación en vez de
  caer al vault. Cinco mutaciones, cinco rojas
  (`tests/oauth2_falsification.py`). El provider es autoalojado; V1-C3 sigue
  siendo host-dependent por la compatibilidad con el IdP real de un operador.
- **Prototipo de sellado TPM** — política de PCR y blob de recuperación offline
  (M12; `SoftwareTpm` es un placeholder, aún no hay camino de hardware real).
- **Recuperación ante crashes** — journal append-only con prefijos de longitud
  y CRC32; una escritura rasgada se detecta y se replay-ea o descarta, nunca
  se aplica a medias (M13).
- **Cuarentena de entorno** — `asv run` limpia las variables con credenciales
  del entorno del agente antes de arrancar la carga de trabajo.

## Qué NO hace (todavía)

Dicho sin adornos, porque un proyecto de seguridad que se sobrevende a sí
mismo no vale nada. Cada punto dice dónde vive su detalle, porque nada de eso
es una suposición:

- **La afirmación sobre memoria sigue siendo la más estrecha, y eso ya es un
  hecho comprobado y no una nota al pie.** Por defecto el broker corre como
  tú, luego un proceso que corre como tú puede leerle la memoria. Lo que los
  tests demuestran es el hecho de kernel que hay debajo: un proceso con el
  mismo uid **sin `CAP_SYS_PTRACE`** es rechazado por el kernel al abrir
  `/proc/<broker>/mem`, y el ataque idéntico contra un *hermano* volcable con
  el mismo uid tiene éxito — así que el rechazo es atribuible al
  endurecimiento y no a que la apertura fallara por otra razón. Un uid aparte
  es lo que hace la negación incondicional, y **ahora el broker puede exigir
  uno**: `--identity-uid` declara el uid que la instalación espera y el binario
  se niega a arrancar con cualquier otro, antes de enlazar su socket o de leer
  la frase de acceso; `--require-dedicated-identity` hace que la *ausencia* de
  una declaración también sea fatal, así que una instalación empaquetada no
  puede degradarse en silencio a la forma de desarrollo.
  `packaging/asv-brokerd.dedicated.service` es la unidad que declara uno. **Lo
  que sigue dependiendo del host es crear la cuenta del sistema y probar la
  unidad en una máquina que tenga una**: este host no tiene `sudo`, y nada en
  el repositorio puede afirmar qué responde `getent passwd` en el tuyo.
- **El ataque del mismo uid se ejecuta ahora, no se documenta.** La cláusula
  más fuerte de UAT-003 estuvo marcada `#[ignore]` durante varios milestones:
  su motivo nombraba el arreglo, *"requiere un proceso hijo que intente la
  apertura"*, y el arreglo nunca se construyó. Corre ahora, y era el único test
  ignorado de la suite. *(Esta línea antes decía que la cláusula seguía
  ignorada. Escribir el test destapó además un defecto real justo al lado:
  bajo `--harden` el broker quedaba fuera de su propio **fichero de
  passphrase**, porque el ruleset se instala al arrancar y la passphrase se
  lee después, y el conjunto de rutas declaradas nunca cubrió el directorio de
  la passphrase. El unit que se envía no pasa `--harden`, y por eso nadie lo
  notó.)*
- **El perfil de hardening M7 es opt-in, no está desconectado.**
  `harden::install_with` se llama desde `crates/broker/src/main.rs:195` tras
  `--harden`; el broker se envía solo con `RLIMIT_CORE=0` cuando no se pasa.
  *(Antes decía que no estaba cableado al binario, y era falso.)*
- **La ruta de instalación verifica una firma, y no se le puede decir que no.**
  `scripts/install.py` exige que `sha256.sum` lleve una firma minisign válida de
  la clave del proyecto antes de leer una sola línea suya, y el manifiesto que
  decide qué componentes se instalan está dentro de esa autoridad firmada. Una
  firma ausente, una inválida, un par archivo/checksums autoconsistente
  publicado por otro, o una clave sustituida son todos rechazos — no hay
  ninguna bandera que rebaje ninguno de ellos. Instalar exige por tanto el
  verificador `rsign`; es una dependencia nueva y deliberada, y
  `tests/provenance_falsification.py` es el recibo.
- **La clave de firma no tiene contraseña.** La clave v0 se genera con
  `rsign generate -W` y está protegida solo por permisos de fichero. Es una
  carencia registrada para cerrar antes de 1.0, no una propiedad.
- **El soporte TPM es un prototipo.** `SoftwareTpm` suplanta al hardware; no
  lo consideres ligado a hardware.
- **Sin redirección de socket eBPF.** El gate de investigación M8 es NO-GO: no
  se escribió ningún programa BPF, y este host de build no puede cargar uno.
  `asv-ebpfd` es el helper de egress/telemetría, que es otro trabajo y no le
  afecta.
- **El puente CONNECT no tiene todavía un listener de producción.** La
  capacidad de sustitución está verificada de extremo a extremo y no está
  cableada en un `asv-brokerd` en marcha, se sirve una petición por túnel, y el
  nonce de la prueba se deriva del destino —lo que resiste que una prueba se
  transfiera a otro destino, pero no es frescura—. Eso es V1-C2, y la fila de
  M9 en el documento de gates dice lo mismo con los recibos detrás.
- **La consola no tiene indicador de interceptación TLS.** Un operador no
  puede ver desde la UI que existe un camino que intercepta. Queda abierto, no
  cerrado.
- **El 1.0 no ha sido declarado.** El mantenedor lo puerta explícitamente; la
  iteración continúa por debajo de 1.0.

## Instalar una release

```bash
# el verificador es obligatorio: el instalador no sigue sin él
cargo install rsign2          # o el gestor de paquetes de tu distribución
curl -LsSf https://raw.githubusercontent.com/Rubentxu/agent-secretless/main/scripts/install.sh \
  | sh -s -- --version 0.37.0 --prefix "$HOME/.local"
```

El instalador exige que `sha256.sum` lleve una firma minisign válida antes de
leer una sola línea suya, y el manifiesto que decide qué componentes se instalan
está dentro de esa autoridad firmada. **El key id de la clave de firma de las
releases es `54CB5B8D3C7419FB`.** Compáralo con esta línea — un dato que puedes
consultar sin descargar lo que estás comprobando. Una descarga que hubiera
sustituido la clave estaría, si no, comprobándose a sí misma.

`release.pub` viaja con la release y **no** es la autoridad: quien sustituye la
descarga sustituye también ese fichero. La autoridad es la clave embebida en el
instalador, y `--trusted-key PATH` acepta una obtenida fuera de banda.

La clave en sí no tiene contraseña (`rsign generate -W`), protegida solo por
permisos de fichero. Es una carencia registrada para cerrar antes de 1.0.

## Inicio rápido

```bash
cargo build --release --workspace
cargo test --workspace --release -- --test-threads=1 \
    --skip uat_028 --skip one_hundred_brokered_reads
# esperado: passed=2081 failed=0 ignored=0
```

2081 y no 2083 porque el comando de arriba se salta dos: `uat_028` levanta un
`sshd` real y necesita un host donde correr, y el presupuesto p95 se afirma por
separado en `--release` para que el inicio rápido siga siendo rápido. Los dos
saltos se cuentan como filtrados, no como ignorados, así que 2081 + 2
filtrados son los 2083 enumerados.

Los dos perfiles se *midieron* por última vez en la certificación de `5873aa4`,
que enumeraba 2049: depuración 114 bloques / 2048 pasadas / 0 fallidas /
1 ignorada / 0 filtradas; release 114 bloques / 2047 pasadas / 0 fallidas /
0 ignoradas / 2 filtradas. Ese recibo se cita en lugar de renumerarse, porque
se tomó sobre un árbol distinto y fingir lo contrario es precisamente el fallo
que esta sección existe para evitar. La aritmética de arriba se vuelve a derivar
de la enumeración viva en cada corrida; la cifra de p95 es el único número de
aquí que es una medición y no una identidad.

Los dos números del recibo citado no son variantes de una misma medición — la
corrida de depuración no lleva ningún
`--skip` y la de release lleva dos, y la fila p95 queda `ignore` en depuración
y se afirma en release.

El paso de build es `--workspace` y no `-p asv-broker` porque las filas
verticales invocan el binario `asv`, que es del crate del CLI, y
`crates/broker/src/binary.rs` **se niega a correr un test contra un binario más
antiguo que sus propias fuentes** — entra en pánico en vez de dejar que un test
mida un programa que no contiene el cambio que se está midiendo. Construir solo
el broker deja ese binario obsoleto y convierte nueve filas que pasaban en nueve
pánicos que todos apuntan al túnel en vez de a la build.

Ese número era `passed=692` en este fichero durante varios milestones, y nada
lo comprobaba: un conteo viejo en un README es una afirmación como cualquier
otra, y este guard (`scripts/check-doc-claims.py`) ahora lo vuelve a derivar en
lugar de dejarlo a la memoria. Al principio comprobaba `passed + ignored` como
una suma, y así es como un `passed=1194` estuvo un tiempo en este bloque: la
suma era correcta, la afirmación era imposible, y un guard que sólo suma no
puede ver que el comando del mismo bloque se salta los dos tests que el número
está contando.

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
  ipc-protocol/   request/response versionado y acotado por longitud (protocolo v11)
  identity/       identidad de carga de trabajo SO_PEERCRED + pidfd
  vault/          envelope cifrado, backup/restore, rekey, prototipo TPM
  policy/         integración Cedar, decisiones deny-by-default
  broker/         manejo de peticiones, sesiones, recovery, daemon asv-brokerd
  cli/            el binario asv: un plano de control, nunca un lector de secretos
  connector-http/ conector GitHub con binding semántico de autoridad
  connector-pg/   conector PostgreSQL (lógica de decisión completa)
  ssh-agent/      servicio de firmas: la clave nunca sale del broker
  ebpfd/          helper de egress/telemetría (8 verbos, sin programa BPF)
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

## Estado de los hitos

**Esta sección era una tabla aquí, y estaba mal.** Marcaba M11, M12 y M13 como
completados con un glifo de tick mientras el documento de gates —la autoridad—
tenía M11 y M12 como **NOT MET** y M13 como **partial**. Una segunda copia del
estado en el fichero más leído del repositorio es una segunda autoridad, que es
justo lo que este proyecto no necesita.

El estado de los hitos vive ahora en un único sitio:
[`16-SECURITY-RELEASE-GATES.md`](agent-secretless-vault-spec/docs/16-SECURITY-RELEASE-GATES.md).
Se comprueba contra el repositorio con `scripts/check-gate-status.py`, así que
rompe el build cuando una fila deja de coincidir con la realidad.

Lo que queda aquí es la secuencia, porque quien quiere saber qué viene ahora no
necesita una tabla de lo que ya pasó:
[`15-ROADMAP.md`](agent-secretless-vault-spec/docs/15-ROADMAP.md) lleva el
camino de v0.28.0 a v1.0 y de ahí a v1.1.

## La postura de seguridad se declara, nunca se implica

Cada integración declara una de estas posturas: `STRONG_SECRETLESS`,
`SHORT_LIVED_EXPOSURE`, `ISOLATED_PROCESS_EXPOSURE`, `RAW_PROCESS_EXPOSURE` o
`UNSUPPORTED` (ADR-0014). Un shim de compatibilidad nunca se etiqueta como
equivalente a firmar o hacer proxy, porque así es como "secretless" se
convierte silenciosamente en una mentira.

## Especificación

`agent-secretless-vault-spec/` contiene el pack completo: 21 documentos, 20
ADRs y un manifiesto `SHA256SUMS` (verificado intacto). Se importa como
investigación y no se edita in situ salvo donde una decisión que registra ya se
ha tomado — cada una de esas ediciones lleva su fecha y su motivo.

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
