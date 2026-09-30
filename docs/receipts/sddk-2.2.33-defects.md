# SDDK 2.2.33 — defectos observados y propuestas de mejora

**Contexto.** Detectado durante el ciclo M9 de `agent-secretless` (`p-20a1ee316faf2ba3/m9-tls-acceptor`), en nueve rondas de limpieza de evidencia. No es el foco del repo: el owner decidió explícitamente el 2026-09-30 que los defectos de SDDK se reportan aparte y no se arreglan aquí.

**Entorno medido.** `sddk 2.2.33`, `source: current`, bundle en `~/.local/share/sddk/framework/2.2.33`. No hay checkout del código fuente de SDDK en esta máquina, así que **ningún defecto de este documento va con línea ni fichero**: son comportamientos observables vía CLI. Para confirmarlos en el código hace falta el repo del framework.

**Alcance de la evidencia.**

| Clase | Significado |
|---|---|
| `OBSERVED` | Reproducido hoy con el comando y la salida citados |
| `INHERITED` | Proviene de un item del ledger, no re-verificado hoy |
| `INFERRED` | Deducido del comportamiento, sin medición directa |

Todos los defectos de la sección 1 son `OBSERVED`. Los de la sección 3 son `INHERITED` y se marcan como tales.

---

## 1. Defectos con impacto en la integridad de la evidencia

### D1 · `uat sign-off` firma un release con plan vacío y sin evidencia

**Severidad: alta. Clase: `OBSERVED`.**

`uat sign-off` escribe un registro de aceptación humana sin exigir escenarios ni evidencia.

```text
# release sin plan: RECHAZADO (correcto)
$ sddk uat sign-off --release v0.9.9 --decision accepted --actor agent:jcode --justification "probe"
error: plan not found: uat-plan-v0.9.9.yaml (run `sddk uat plan --release v0.9.9` first)

# plan presente pero VACÍO: ACEPTADO
$ sddk uat plan --release v0.9.9 --output uat-plan-v0.9.9.yaml
rc=0   features: []   scenarios=0        # el propio uat plan genera el esqueleto vacío
$ sddk uat sign-off --release v0.9.9 --decision accepted --actor agent:jcode --justification "probe D1bis"
uat sign-off recorded: .../uat/acceptances/uat-acceptance-v0.9.9.yaml
```

D1 y D6 encadenan: como `uat plan` no genera escenarios (D6), el plan que produce es exactamente el que `sign-off` acepta sin examinar. No hace falta escribir nada a mano para llegar al registro sin evidencia.

El registro resultante:

```yaml
decision: accepted
actor: agent:jcode
justification: probe D1bis
evidence_snapshot_sha256: sha256:{}      # vacío
outstanding_findings: []
plan_version_sha256: sha256:a458b7fc...
```

Con `--actor` libre, un agente puede producir un registro indistinguible de una aprobación humana, sin una sola evidencia, sobre un release con cero escenarios comprobados.

**Mejora propuesta.**

1. Exigir `scenarios` no vacío antes de firmar.
2. Rechazar `--actor` con patrón de agente cuando la decisión sea `accepted`, o exigir un flag explícito tipo `--agent-authored` que marque el registro como no humano.
3. Poblar `evidence_snapshot_sha256` con el hash real del report; un `{}` debería abortar, no aceptarse.
4. Añadir gate que exija `outstanding_findings: []` respaldado por evidencia, y no por defecto.

**Nota de alcance.** El hash de plan sí se calcula, así que el registro no es puramente ficticio: el defecto es que no comprueba que el plan tenga contenido ni que exista un report asociado.

---

### D2 · La identidad del proyecto se deriva de la URL del remoto y no hay forma de fijarla

**Severidad: alta. Clase: `OBSERVED`.**

`project_id` se deriva de la URL del remoto, y un cambio de caracteres normaliza a un proyecto distinto. Lo grave no es el identificador: es que **los writes tienen éxito en el ledger equivocado, sin aviso**.

```text
$ git remote set-url origin https://github.com/Rubentxu/agent-secretless.git
$ sddk project resolve --root . --scope .
project_id: p-4599f628027225cf        # distinto
$ sddk backlog list --root . --scope .
(0 items)                               # el ledger real queda ciego, sin error

$ git remote set-url origin https://github.com/rubentxu/agent-secretless.git
$ sddk project resolve --root . --scope .
project_id: p-20a1ee316faf2ba3        # restaurado
```

Peor: con la URL rota, un `backlog capture` **devuelve éxito** con `event_id: 1` en un ledger nuevo y vacío. El ledger real queda intacto (436 eventos, ciclo `CLOSED`) y el item escribía en otra parte, sin warning ni código de salida distinto de cero.

Medido además:

- `sddk project` sólo expone `resolve`. No hay `set`, `use`, `pin` ni `adopt` de identidad.
- `SDDK_PROJECT_ID` **no es un override**: no aparece en el bundle 2.2.33 y, forzado a un id ajeno con la URL correcta, la resolución sigue devolviendo el proyecto real.
- `project_id` **y** `workspace_id` cambian ambos con el case de la URL, así que ninguno sirve de pin. Lo único estable es la ruta del filesystem, que es convención del usuario, no un mecanismo.

**Mejora propuesta.**

1. Derivar el `project_id` del path canónico del workspace como fuente primaria, y usar la URL como confirmación, no como generador. El path es estable frente a cambios de remote.
2. Si la URL cambia y resuelve a un proyecto sin eventos, exigir confirmación explícita en vez de materializar un ledger vacío en silencio.
3. Añadir `sddk project set` / `pin` para fijar identidad de forma sancionada.
4. **Documentar `SDDK_PROJECT_ID`** si existe como override real, o eliminarlo: hoy no está documentado y no funciona, combinación peligrosa porque parece una salida.

---

### D3 · `backlog discard` destruye hallazgos sin dejar rastro

**Severidad: media-alta. Clase: `OBSERVED`.**

`backlog discard` marca el item como `discarded` y no comprueba que su contenido haya sido re-declarado en otro sitio. Un item puede contener varios hallazgos y supersederlo se lleva todos los que no se hayan copiado.

Caso real, no hipotético: al superseder `bl-bl-01M3RYA5J3000387HWP0WSYVR0` para registrar D1, se perdió un segundo hallazgo no relacionado que vivía sólo en ese item (`uat plan` emite `features: []` y cero escenarios). Pasó inadvertido durante un ciclo entero.

**Mejora propuesta.**

1. `discard` debería exigir `--superseded-by <item-id>` y verificar que ese item mencione al descartado.
2. Opcional: diff de contenido en la CLI, avisando si el sucesor es más corto que el predecessor. En este repo los cuatro sucesores legítimos eran más largos; el destructivo no lo era.
3. Documentar la semántica: `discard` no es archivar. Descartado sigue legible vía `backlog show`, y el texto permanece en el historial de `BACKLOG.md`, así que nada se pierde del todo. Eso reduce la severidad respecto a una pérdida real, pero el hallazgo desaparece del estado vivo sin que nadie lo note.

---

## 2. Defectos de la CLI de UAT

### D4 · `uat status` resuelve rutas por CWD

**Severidad: media. Clase: `OBSERVED`.**

```text
$ sddk uat status --release v0.15.0 --format json
{"release":"v0.15.0","plan":"generated","report":"ready"}      # desde la raíz

$ cd crates/tls-acceptor && sddk uat status --release v0.15.0 --format json
{"release":"v0.15.0","plan":"missing","report":"not-ready"}    # mismo repo
```

Un `status` que devuelve "missing" para un release cuyo plan existe es peor que uno que falla: se lee como ausencia de evidencia.

Radio de impacto acotado: `uat review` y `uat dashboard` toman rutas explícitas y funcionan desde un subdirectorio. Sólo `uat status` sufre esto.

**Mejora propuesta.** Resolver las rutas desde `--root`/workspace, con el CWD sólo como último recurso. O fallar con un mensaje claro si no hay plan en el CWD.

---

### D5 · `uat plan --from` no valida el release de partida

**Severidad: baja. Clase: `OBSERVED`.**

```text
$ sddk uat plan --release v0.18.0 --from banana --output /tmp/z.yaml
rc=0
$ grep last_uat_release /tmp/z.yaml
  last_uat_release: banana
```

Un tag inexistente o una cadena arbitraria se copia literalmente al plan, que queda declarando una base inexistente.

**Mejora propuesta.** Validar `--from` contra tags semver reales antes de emitir el plan; error no-cero si no resuelve.

---

### D6 · `uat plan` nunca genera escenarios

**Severidad: media. Clase: `OBSERVED`.**

```text
$ sddk uat plan --release v0.18.0 --output /tmp/z2.yaml
rc=0   features: []   scenarios=0
```

`features` e `id: S-` son `[]`/0 tanto con `--from` como sin él. La cadena `plan → execute → report` no arranca sola: hay que escribir el plan a mano.

**Mejora propuesta.** Derivar `features` y `scenarios` del diff contra `--from` o del release previo. Si no puede inferirlos, al menos documentar que `uat plan` produce un esqueleto y que el contenido es manual.

---

### D7 · `backlog render` sobrescribe en silencio, no hay verificación de drift

**Severidad: baja. Clase: `OBSERVED`.**

`sddk backlog` expone sólo `render`. No hay `verify` ni `check` de drift. Al mutar `BACKLOG.md` a mano y ejecutar `render`, el archivo se sobrescribe en sitio con el contenido derivado del ledger, sin warning:

```text
sha del ARCHIVO mutado    : 4219b87cfc3b9ce6
sha del ARCHIVO tras render: ec31172927a2bb1c   # restaurado
```

`render` es idempotente (dos ejecuciones seguidas dan el mismo sha), así que la proyección no puede divergir del ledger. Lo que falta es señal: nada indica que el archivo fue reescrito ni que la edición manual se perdió.

**Mejora propuesta.** `sddk backlog check` que compare el archivo contra el contenido derivado y salga distinto de cero ante drift, para usarlo en CI. `render --check` sería suficiente.

---

## 3. Observado en el ledger, no re-verificado hoy

Estas entradas se recuperaron durante la auditoría de linaje. Son `INHERITED`: no las he reproducido en esta sesión, así que no deben darse por confirmadas sin una comprobación rápida.

| Defecto | Detalle |
|---|---|
| Gate `release-receipt` sin evaluador registrado | `release.complete` exige gates `no-pending-effects` + `release-uat-approved` y artefactos `merge-receipt` + `release-receipt`. `release-receipt` es un artefacto, así que el motor responde `ENGINE_UNREGISTERED_EVALUATOR`. Fuente actual: `prompts/sddk/git-contract.md:87` |
| Prompt de release desalineado del motor | `prompts/sddk/phases/release.md:109` y `:178` instruyen evaluar `--gate release-receipt`. Seguir el prompt al pie de la letra cuesta un intento de gate desperdiciado y un receipt ausente |
| No hay schema de `report` ni de `session` | `uat validate` y `uat migrate-plan` parsean ambos como `UatPlan`. El lado sano funciona: `migrate` migra v1→v2 y `validate` da OK sobre plan sano |
| Ingest multi-sesión pisa el resultado | `uat_results` guarda una fila por (proyecto, tag) e `ingest --session` la REEMPLAZA, así que 9 sesiones de un escenario dejan `session_count=1` con `coverage_pct=100` |

La primera y la segunda son el mismo defecto visto desde los dos lados, y afectan a cualquiera que siga el prompt de release.

---

## 4. Lo que ya está bien (para no romperlo al arreglar)

- `ledger verify` es fiable y rápido: 436 eventos, hash verificable.
- `backlog show` lee items descartados, así que el texto no se pierde al superseder.
- Los items descartados siguen presentes en el historial de `BACKLOG.md`.
- `render` es idempotente.
- `uat sign-off` rechaza releases sin plan.
- `uat review` y `uat dashboard` funcionan desde subdirectorios con rutas explícitas.

---

## 5. Orden de arreglo sugerido

1. **D1** — un agente puede fabricar una aceptación humana. Es el único con capacidad de contaminar la evidencia de release.
2. **D2** — evitar la divergencia silenciosa de ledger. Se pierde trabajo sin error visible.
3. **D3** — el guard de linaje ya está escrito y falsificado en `agent-secretless` (`scripts/backlog-lineage-check.py`); tras el arreglo de D3 podría mudarse al framework.
4. **D4, D6** — ergonomía hidro: `status` no debe reportar evidencia ausente cuando existe, y `plan` debe producir escenarios usables. Sin riesgo de integridad.
5. **D5, D7** — ergonomía de bajo riesgo, sin impacto en la integridad de la evidencia.
6. **Sección 3** — requiere el repo del framework para confirmarse; no lo he tocado.

---

## 6. Reproducir

Todos los comandos de la sección 1 son reproducibles en `agent-secretless` sin efectos colaterales, salvo D1, que escribe un registro de aceptación: hay que borrarlo después.

```text
sddk version                    # 2.2.33
sddk project resolve --root . --scope .
cd crates/tls-acceptor && sddk uat status --release v0.15.0 --format json && cd -
git remote set-url origin https://github.com/Rubentxu/agent-secretless.git
sddk project resolve --root . --scope .   # project_id distinto
git remote set-url origin https://github.com/rubentxu/agent-secretless.git
```

El orden importa: `git remote set-url` muta estado real. Devuélvalo siempre, aunque el comando intermedio falle.
