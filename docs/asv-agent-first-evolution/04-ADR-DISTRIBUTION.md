# ADR — Distribución como un producto con runtime privado

**Estado propuesto:** Accepted

## Contexto

El workspace actual produce varios ejecutables. Uno de ellos, `asv-vault-tool`, existe explícitamente para el harness adversarial y no debería confundirse con un componente de usuario.

Al mismo tiempo, fusionar `asv` y `asv-brokerd` sólo para ofrecer un único fichero degradaría una frontera de confianza útil.

## Decisión

Distribuir el core como un único producto con dos componentes runtime:

```text
PUBLIC
  asv

PRIVATE RUNTIME
  asv-brokerd

NOT SHIPPED
  asv-vault-tool

OPTIONAL SEPARATE PACKAGE
  asv-console
```

## Layout

### User-local

```text
~/.local/bin/asv
~/.local/libexec/asv/asv-brokerd
~/.config/systemd/user/asv-brokerd.service
```

### System

```text
/usr/bin/asv
/usr/libexec/asv/asv-brokerd
/usr/lib/systemd/user/asv-brokerd.service
```

## Manifiesto de release

Debe existir un manifiesto explícito, por ejemplo `distribution/manifest.toml` o equivalente, con cada componente y su clase.

El documento normativo debe exigir:

```text
asv              required/public
asv-brokerd      required/private
asv-console      optional/ui
asv-vault-tool   forbidden/production
```

El formato concreto puede emerger durante implementación, pero la clasificación no.

## Canales de instalación

### P0 — archive oficial firmado

Artefactos por target:

```text
agent-secretless-vX.Y.Z-x86_64-unknown-linux-gnu.tar.zst
agent-secretless-vX.Y.Z-aarch64-unknown-linux-gnu.tar.zst
manifest.toml
sha256.sum
sha256.sum.minisig
release.pub
SBOM
```

**`checksums.txt` fue sustituido por `sha256.sum` durante la implementación, y
el motivo no es cosmético.** El Tren de release firmaba `sha256.sum` —que es lo
que `dist` produce— mientras el instalador leía `checksums.txt`, un nombre que
aparece en esta decisión y que **nada en el repositorio ha escrito nunca**. El
arnés de tests lo sintetizaba, de modo que la suite verde era la prueba del
hueco y no la razón de que fuese invisible. Con dos autoridades de checksum y
ninguna comprobando a la otra, además, la firma no cubría lo que el consumidor
leía. Hoy hay una sola autoridad y es la firmada: `scripts/install.py` verifica
`rsign` sobre `sha256.sum` **antes** de abrirlo, y el manifiesto que decide qué
componentes se instalan está dentro de esa autoridad mediante
`scripts/pin-manifest-into-checksums.py`. Un `release.pub` que viaja con la
descarga no es la autoridad: lo decide una clave embebida en el instalador, cuyo
key id (`54CB5B8D3C7419FB`) se publica aquí y en el anuncio de release para
compararlo fuera de banda. La recepción es
`tests/provenance_falsification.py`.

### P0 — installer fino

El instalador:

1. detecta plataforma/arquitectura;
2. selecciona release/canal;
3. descarga manifiesto y artefacto;
4. verifica integridad/firma;
5. instala componentes declarados;
6. ejecuta `asv setup` o indica cómo hacerlo;
7. nunca compila Rust en la máquina destino.

### P1 — mise

Mise instala la misma unidad versionada, no sólo `asv`:

```text
<install-root>/bin/asv
<install-root>/libexec/asv-brokerd
```

`asv setup` registra el servicio apuntando al broker de esa instalación.

### P2 — DEB/RPM/Homebrew/Nix/AUR

Se añaden sólo cuando el core P0/P1 sea estable. Los package managers conservan ownership de actualización.

### GUI

`asv-console` se distribuye por separado mediante mecanismos Tauri apropiados. No debe duplicar vault/broker.

## Actualización

`asv doctor --json` debería exponer, cuando sea posible:

- `installed_via`;
- versión CLI;
- versión broker;
- compatibilidad de protocolo.

`asv update` no debe competir con el package manager. Si la instalación es gestionada por mise/apt/rpm/homebrew, informa del mecanismo correcto.

## Gate obligatorio

El bundle de producción falla si contiene cualquier ejecutable no declarado.

Esto convierte el error observado con `asv-vault-tool` en una propiedad verificable, no en una convención.
