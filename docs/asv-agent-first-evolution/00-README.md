# ASV Agent-First Distribution & Hypermedia CLI Evolution

## Propósito

Este paquete define un evolutivo **pequeño, incremental y compatible** para Agent Secretless Vault (ASV) centrado en cuatro problemas concretos:

1. distribuir el producto sin exponer binarios de test ni obligar al usuario a conocer procesos internos;
2. facilitar instalación, bootstrap, diagnóstico y actualización;
3. convertir la CLI en una superficie **autodescubrible y navegable por agentes**, inspirada en HATEOAS pero adaptada a una CLI local;
4. publicar una skill oficial en `Rubentxu/agent-skill` compatible con el patrón actual del repositorio y con skills.sh.

No se propone una reescritura del broker, un runtime de prompts, un MCP nuevo ni un motor de workflows. La intención es reforzar la experiencia agent-first utilizando capacidades que ASV ya posee.

## Decisiones principales

- `asv` sigue siendo la única interfaz pública que debe conocer un usuario o agente.
- `asv-brokerd` sigue siendo un binario privado y separado por frontera de confianza.
- `asv-vault-tool` se clasifica como herramienta de harness/test y queda **prohibido en paquetes de producción**.
- `asv-console` permanece opcional y distribuido separadamente de la CLI/core.
- Las skills **no se compilan ni embeben en ASV**. Viven en `Rubentxu/agent-skill`.
- La CLI expone un contrato estructurado (`--json`) con relaciones tipadas y siguientes acciones disponibles.
- La skill aprende a navegar ese contrato; no replica el workflow interno de ASV ni las reglas Cedar.
- En v1 del evolutivo no se crea `asv agent next` como motor de estado. Cada respuesta expone sus siguientes relaciones; si la evidencia posterior demuestra que hace falta un coordinador explícito, se diseña en otro evolutivo.

## Relación con el roadmap actual

El roadmap actual tiene M13 como estabilización RC y congela nuevas familias amplias de conectores, no mejoras de distribución o agent UX. Este paquete propone integrarlo como **incremento transversal M13-DX: Agent-first distribution & discoverability**, antes del corte de una release candidata certificable.

No se recomienda crear M14 para este trabajo: el cambio es transversal, pequeño y orientado a hacer distribuible y operable lo ya construido.

## Contenido

- `01-SPECIFICATION.md` — requisitos funcionales, de seguridad y de compatibilidad.
- `02-ARCHITECTURE.md` — arquitectura y separación determinista/agentic.
- `03-ADR-HYPERMEDIA-CLI.md` — decisión sobre CLI navegable tipo HATEOAS.
- `04-ADR-DISTRIBUTION.md` — frontera de producto y empaquetado.
- `05-ADR-SKILLS.md` — relación entre ASV, agent-skill y skills.sh.
- `06-CLI-CONTRACT.md` — contrato JSON y vocabulario de relaciones.
- `07-ROADMAP.md` — hitos pequeños y orden de implementación.
- `08-AAT-UAT.md` — pruebas de aceptación agent-first y humanas.
- `09-IMPLEMENTATION-GUIDE.md` — propuesta de cambios por módulo.
- `10-MIGRATION-ADOPTION.md` — cómo adoptar el evolutivo sin romper usuarios actuales.
- `11-RISKS-OPEN-QUESTIONS.md` — riesgos y decisiones futuras.
- `12-TRACEABILITY.md` — trazabilidad entre requisitos, artefactos y pruebas.
- La skill `agent-secretless` está **publicada** en
  `Rubentxu/agent-skill/skills/agent-secretless` (commit `1778767`). El
  `proposed-skill/agent-secretless/` de este directorio era el borrador y ya no
  se mantiene aquí: ADR-05 la excluyó como fuente canónica y el contrato
  rechaza ejecutarse contra cualquier ruta dentro de este repo.

## Baseline observado

A fecha de elaboración:

- el workspace principal declara `asv`, `asv-brokerd` y `asv-vault-tool` como binarios;
- `asv-vault-tool` se describe en su propio código como ejercitador mínimo para el harness adversarial;
- `apps/desktop` es un workspace separado y declara `asv-console`;
- la CLI `asv` ya dispone de `status`, sesiones, `run`, gestión de metadatos/credenciales y operaciones del broker, pero su salida es principalmente humana;
- `Rubentxu/agent-skill` utiliza skills autocontenidas con `SKILL.md`, referencias bajo demanda, tests/evals y validación local de rutas/frontmatter;
- skills.sh instala skills desde repositorios GitHub y descubre cada `SKILL.md` válido.

## Resultado esperado

Un usuario debería poder llegar a:

```bash
curl -fsSL https://get.agent-secretless.dev | sh
asv setup
asv doctor
asv run -- <comando>
```

Un agente debería poder empezar siempre por:

```bash
asv agent discover --json
```

y continuar **sólo por relaciones anunciadas por ASV**, sin pedir ni recuperar material secreto y sin memorizar un workflow estático.
