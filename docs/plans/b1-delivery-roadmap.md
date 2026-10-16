# Roadmap de entrega — serie B1 (continuación) y camino a v1.0

> **Autoridad.** El plan secuencial vigente sigue siendo
> `agent-secretless-vault-spec/docs/15-ROADMAP.md` (R0–R10). Este documento NO lo
> reemplaza: ordena los **bloques de entrega** que cierran los huecos medidos en la
> auditoría de `6ca2984` y termina de consumir los incrementos abiertos del roadmap.
> Respeta y continúa la serie `b1.*` ya abierta en `b1/worker-lifetime`
> (B1.1–B1.6 con receipts en `docs/receipts/` y notas en `docs/release-notes/`).

## Dónde estamos (medido sobre el remoto, 2026-10-13)

| Qué | Estado |
|---|---|
| `origin/main` publicado | `dcc98ae` = **v0.38.3** |
| Rama `b1/worker-lifetime` | `6ca2984`, **39 commits por integrar a main, 0 por traer** |
| Serie B1 en vuelo | B1.1–B1.6 entregados con tag (`b1.4`, `b1.5`, `b1.6`), receipt y release-notes |
| Gate `spec-integrity` | **EN ROJO también en main**: `SHA256SUMS` espera `c0646a6b…`/`f28b8029…` y los archivos `15-ROADMAP.md`/`16-SECURITY-RELEASE-GATES.md` hashean `71e8a3d2…`/`7b425701…` |
| Gate-map | `tools/check-gates.py`: 40/40 UAT con gate, 0 defectos duros, **7 warnings** |
| Auditoría de `6ca2984` | H-01…H-08 confirmados (ver bloques B1.7–B1.11) |

## Cómo se trabaja cada bloque (patron de la casa, ya en uso)

1. **Spec DRAFT** breve en `docs/receipts/` (solo si el bloque cambia contrato).
2. **Commits unidad** (≤ ~400 líneas, tests y docs junto al código, Conventional Commits).
3. **Pruebas efímeras del bloque** en `tests/ephemeral/<bloque>/`, nombres `eph_*`
   (NUNCA `uat_*`: un archivo llamado `uat_*` sin id declara un UAT falso y ensucia
   el gate-map, ver warnings actuales de `tools/check-gates.py`).
4. **Receipt** de implementación en `docs/receipts/`.
5. **Borrado de las pruebas efímeras** en el último commit antes del tag: el tree
   etiquetado queda limpio. Los UAT **permanentes** ya existentes no se tocan: son la
   certificación del roadmap (`13-TEST-STRATEGY.md`, `14-UAT-ADVERSARIAL.md`).
6. **Release + integración remota**: release-notes en `docs/release-notes/`, tag
   anotado `b1.N`, `python3 scripts/check-release-bump.py`, merge a `main`, push,
   `scripts/publish-release.sh --confirm --draft` (autoridad A1–A4 verificada por
   `scripts/check-release-authority.py`, exigida por `16-SECURITY-RELEASE-GATES.md`).

**Lentes obligatorias de cierre de bloque** (router de pruebas efímeras): cada bloque
debe pasar por (a) *valor* — ¿el operador/agent percibe la mejora?; (b) *riesgo* —
¿la prueba efímera reproduce el defecto antes del fix (RED)?; (c) *regresión* —
¿la suite permanente cubre el comportamiento tras borrar la efímera?
> Nota de herramientas: la skill `delivery-first-testing` **no existe** en el registro
> de skills de esta máquina. Se usa el equivalente disponible: `distribution-first-release`
> (mecánica de release), `tdd` (RED→GREEN) y `work-unit-commits` (troceado).

---

## B1.7 — Verdad documental y gates [PARALELIZABLE: 3 agentes]

**Objetivo:** que el pipeline vuelva a ser creíble. Desbloquea todo lo demás.

- [ ] **T1** Re-fijar `agent-secretless-vault-spec/SHA256SUMS` para `15-ROADMAP.md` y
  `16-SECURITY-RELEASE-GATES.md` con commit que explique QUÉ cambió y por qué (o
  revertir el cambio si fue accidental). Ref: stage `spec-integrity` de `pipeline.kts`.
- [ ] **T2** Actualizar comentarios obsoletos: `pipeline.kts:129-143` (deuda clippy 263
  → baseline 0) y stage `spec-gates` (34/34 → 40/40 + 7 warnings); badge de
  `README.md:3` apunta a `.github/workflows/verify.yml` que no existe.
- [ ] **T3** Cerrar los 7 warnings de `tools/check-gates.py`: declarar el UAT id en
  `uat_011_redirect_denier.rs`, `uat_012_trust_injection.rs`, `uat_017_env_scan.rs`,
  `uat033_live.rs`, y dar UAT id a los bloques de salida M14/M15.
  Ref: `14-UAT-ADVERSARIAL.md`.
- [ ] **T4 (efímero, se borra al cierre)** `tests/ephemeral/b1-7/eph_gates_truth.py`:
  corre `sha256sum --check` del spec pack + `check-gates.py` y exige 0 warnings.
  Al cierre queda cubierto por los stages permanentes `spec-integrity` y `spec-gates`.
- Superficies disjuntas → T1/T2/T3 en paralelo (agent teams). **Cierre:** tag `b1.7`,
  merge a `main`, push.

## B1.8 — Evidencia de auditoría observable [SECUENCIAL]

**Objetivo:** que un fallo de escritura del audit trail sea visible, no silencioso (H-02).

- [ ] **T1** RED: test unitario que inyecta error de IO en el archivo de auditoría y
  afirma que el fallo queda registrado (hoy `lib.rs:1457` lo descarta con `let _`).
- [ ] **T2** Propagar: `tracing::error!` con seq/hash + marca de salud de auditoría
  consultable. Ref: `11-AUDIT-OBSERVABILITY.md` (evidencia de uso/sesión/policy).
- [ ] **T3** E2E efímero: `tests/ephemeral/b1-8/eph_audit_gap.rs` — brokerd real sobre
  UDS en `tmpdir`, archivo de audit no escribible → el estado del broker lo refleja.
  AAT: la salida que lee el operador nombra el hueco sin buscar en logs.
- [ ] **T4** Borrado de efímeros + receipt + release `b1.8`.
- No paralelizable con B1.9 (mismo `crates/broker/src/lib.rs`).

## B1.9 — Pin de sesión vivo (pidfd) [SECUENCIAL]

**Objetivo:** que la propiedad de una sesión se pruebe con el proceso vivo, no solo
con el número de PID (H-03). Ref: `08-IDENTITY-POLICY-CAPABILITIES.md`, ADR-0003
(`agent-secretless-vault-spec/adrs/0003-…`), UAT-030 en `14-UAT-ADVERSARIAL.md`.

- [ ] **T1** RED: test que simula reciclaje de PID y muestra que `belongs_to`
  (`lib.rs:389-395`) acepta un proceso distinto cuando el pidfd ya se cerró.
- [ ] **T2** Guardar el `OwnedFd` en el registro de sesión vía `into_pidfd()`
  (hoy sin llamadores) y re-verificar liveness en cada uso de sesión.
- [x] **T3** E2E efímero: `crates/broker/tests/eph_pin_liveness.rs` — hijo real que
  abre sesión, muere; otro proceso recicla el PID y es rechazado.
  AAT: fila de audit dice `pidfd-pinned` solo con pin vivo.
- [ ] **T4** Borrado de efímeros + receipt + release `b1.9`.

## B1.10 — Journal de recuperación: cableado o retirado [SECUENCIAL]

**Objetivo:** decidir y ejecutar una sola verdad sobre el crash-recovery (H-04).
El spec ya decide: UAT-035 es normativo de M13 en `14-UAT-ADVERSARIAL.md`
→ **cablear**, no retirar.

- [ ] **T1** RED: UAT-035 existe pero prueba el módulo aislado; añadir la fila que
  falta: arranque productivo con replay.
- [ ] **T2** Cablear en `broker/src/main.rs`: append pre-mutación + fsync + replay en
  arranque, usando `RecoveryJournal` tal cual. Ref: `03-ARCHITECTURE.md`.
- [ ] **T3** Corregir los comentarios que hoy describen un journal inexistente:
  `Cargo.toml` (`[profile.dist]`) y `packaging/asv-brokerd.service:62`.
- [ ] **T4** E2E efímero: `tests/ephemeral/b1-10/eph_crash_replay.py` — SIGKILL al
  brokerd entre mutaciones, reinicio, estado reconciliado.
  AAT: `asv doctor` reporta el replay en lenguaje de operador.
- [ ] **T5** Borrado de efímeros + receipt + release `b1.10`.

## B1.11 — Frontera OAuth2 [SECUENCIAL, tests en paralelo al final]

**Objetivo:** que nada que un IdP devuelva llegue al agente sin saneamiento, y que el
refresh no corrompa tokens (H-05, H-06). Ref: `15-ROADMAP.md` (M11 / fila R2.B),
`02-THREAT-MODEL.md`.

- [ ] **T1** RED saneamiento: issuer efímero local (`oauth2_test_support.rs`) que
  refleja un secreto falso en el cuerpo de error → hoy llegaría al `message`.
- [ ] **T2** Un único punto de saneamiento para cuerpos de error del token endpoint,
  misma regla que ya aplica el camino del resource server (`oauth2_binding.rs:323-331`).
- [ ] **T3** RED + fix refresh: token `a+b` debe sobrevivir una sola codificación
  (`oauth2.rs:633-640` + `:598-609` hoy doble-codifican).
- [ ] **T4** E2E efímero: `tests/ephemeral/b1-11/eph_oauth2_boundary.rs` — flujo
  whoami contra issuer efímero hostil; AAT: el error del CLI no contiene el secreto.
- [ ] **T5** Borrado de efímeros + receipt + release `b1.11`.

## B2.1 — Verticales socket-level [PARALELIZABLE: 4 agentes, superficies disjuntas]

**Objetivo:** consumir el increment abierto y repetido en `15-ROADMAP.md` (filas
R2.C/R2.D/R2.E/R2.F): la operación está cableada, falta el vertical contra socket real
(origen **efímero local**, nunca cloud).

- [ ] **AWS** (STS regional) — `crates/broker/src/aws/` + origen TLS efímero.
- [ ] **Kubernetes** — `crates/broker/src/k8s/` + API server efímero.
- [ ] **mTLS** — `crates/broker/src/mtls/` + CA/llavero efímero.
- [ ] **Registry** — push como sesión `POST`→`PUT` con `Location` vetado (follow-up
  declarado de R2.F) — `crates/connector-http/src/registry.rs`.
- Cada vertical: operación real + filas adversariales + una prueba efímera
  `tests/ephemeral/b2-1/eph_<provider>/` borrada al cierre. Ref de criterio de salida:
  tabla R2 de `15-ROADMAP.md`. **Cierre:** receipt único + release `b2.1`.

## B3.0 — Certificación v1.0 (R5) [SECUENCIAL]

**Objetivo:** congelar alcance y certificar. Ref: `15-ROADMAP.md` R4/R5, ADR-0020,
`16-SECURITY-RELEASE-GATES.md`.

- [ ] Matriz de release limpia y `check-documented-install.py` desde máquina sin
  árbol fuente; gates con PASS/FAIL/SKIPPED/UNAVAILABLE_SUBSTRATE distinguibles.
- [ ] Entrada de M15 en operator UX (lo único que R4 declara abierto).
- [ ] AAT efímera final: instalación documentada completa en HOME vacío (se borra tras
  la certificación; la permanente ya vive en `scripts/check-documented-install.py`).
- [ ] **Cierre:** tag `v1.0.0` según la ley de `scripts/check-release-bump.py`.

---

## Anexo — Glosario (lenguaje ubicuo del proyecto)

| Término | Significado en este proyecto |
|---|---|
| **Agent** | Proceso (humano o IA) que pide credenciales al broker por IPC; nunca ve el secreto. |
| **Broker** | `asv-brokerd`: único proceso que autoriza, audita y entrega; el dominio no confía en el agente. |
| **Vault** | Almacén cifrado de credenciales (`crates/vault`); clase de exportabilidad por credencial. |
| **Surrogate** | Credencial temporal acuñada para una sesión con pin vivo; muere con la sesión. |
| **Receipt** | Documento `asv.integrations.execute/v1` con lo pedido, lo prometido y lo ocurrido; re-chequeable sin broker. |
| **ActionIntent / PlanBinding** | Autoridad ligada a una operación concreta (R4), no a una sesión; el binding es lo prometido del mundo. |
| **Pin / pidfd** | Descriptor del kernel que referencia UN proceso vivo; elimina la ambigüedad de reciclaje de PID (ADR-0003). |
| **CONNECT bridge** | Proxy TLS que sustituye credenciales en tránsito (M9); sustitución auditada. |
| **Vertical** | Proveedor completo: operación real + propiedad secretless + filas adversariales (criterio R2). |
| **UAT** | Prueba de aceptación de salida de un milestone, permanente y gateada (`14-UAT-ADVERSARIAL.md`). |
| **E2E** | Prueba que arranca en la superficie de producto (CLI/IPC/binary), no llamando funciones internas. |
| **AAT** | Acceptance test: lo que un operador lee y acepta como bueno (salida de `doctor`, receipts). |
| **Efímero (test)** | Prueba que nace de un criterio de UN bloque, vive en `tests/ephemeral/<bloque>/` y se borra antes del tag. |
| **Gate** | Comprobación obligatoria del pipeline; un gate que no puede correr es `UNAVAILABLE_SUBSTRATE`, nunca PASS. |
| **Substrate** | Entorno externo que una prueba necesita (PostgreSQL, userns, hardware); su ausencia se declara, no se simula. |
| **Ratchet** | Métrica que solo puede bajar (`scripts/check-clippy-ratchet.py`): la deuda no crece. |
| **Spec pack** | `agent-secretless-vault-spec/`: normativo, importado byte-a-byte y verificado con `SHA256SUMS`. |
| **DRAFT / Receipt** | Spec provisional de un bloque / evidencia de lo implementado (`docs/receipts/`). |
| **Release authority** | Ley A1–A4: tags anotados, ancestros, consistencia local/remota (`scripts/check-release-authority.py`). |
| **Bloque (b1.N)** | Unidad de entrega de valor que termina en tag + merge a main + push; la serie continúa B1.7… |
| **R-block (R0–R10)** | Bloques de trabajo del roadmap authority; NO son gates ni releases. |
