# Trazabilidad

| Requisito | Implementación esperada | Evidencia/Prueba |
|---|---|---|
| FR-001 manifiesto producto | `distribution/*` | UAT-DX-001 |
| FR-002 layout privado | packaging/setup | UAT-DX-002 |
| FR-003 setup idempotente | CLI setup | UAT-DX-003 |
| FR-004 doctor | CLI doctor | UAT-DX-004/005 |
| FR-005 discover | CLI agent | AAT-001/002 |
| FR-006 envelope | schema Rust + renderer | contract tests, AAT-008 |
| FR-007 links tipados | AgentRel/AgentLink | AAT-003/007 |
| FR-008 capabilities honestas | discovery builder | AAT-005 |
| FR-009 JSON selectivo | renderers | UAT-DX-005 |
| FR-010 human default | human renderer | UAT-DX-005 |
| FR-011 errors navegables | error mapping | AAT-002/005 |
| FR-012 skill oficial | `agent-skill` | UAT-DX-006 |
| FR-013 skill runtime-driven | SKILL/evals | AAT-003/004/005 |
| FR-014 instalación skill | skills CLI | UAT-DX-006 |
| SR-001 no secrets | all agent output | AAT-006 + adversarial suite |
| SR-002 no sh-c | invoke contract | AAT-007 |
| SR-003 no auto-approval | skill/router | AAT-004 |
| SR-004 no Cedar duplication | architecture review | skill eval/review |
| SR-005 mismatch fail closed | schema validation | AAT-008 |
| SR-006 harness excluded | packaging gate | UAT-DX-001 falsification |
| SR-007 no roadmap capability inference | discover runtime | AAT-005 |

## Trazabilidad con el baseline actual

### `asv-vault-tool`

El propio binario se describe como herramienta mínima para el harness adversarial. Por ello se clasifica como `test-harness` y no se elimina del código: se excluye del producto distribuido.

### `asv-brokerd`

El crate se define como proceso secret-bearing. Se mantiene como runtime privado separado; el evolutivo cambia su presentación/instalación, no la frontera de confianza.

### `asv-console`

El workspace Tauri está separado del workspace principal por dependencias GUI. Se conserva como paquete opcional.

### Roadmap M13

M13 ya contiene package hardening, docs/manual, signed artifacts y RC stabilization. M13-DX concreta la parte de distribución/operabilidad agent-first sin añadir nuevas familias de conectores.

### Shell-first integration

La especificación existente afirma que el agente debe poder seguir usando herramientas normales sin pedir/copiar tokens. La skill propuesta refuerza esa intención: guía al agente hacia ASV, nunca hacia secret retrieval.

## Fuentes externas de compatibilidad

A fecha de elaboración:

- skills.sh documenta instalación con `npx skills add <owner/repo>` y soporte de instalación selectiva;
- los packs/skills válidos requieren `SKILL.md` con `name` y `description`;
- el patrón de progressive disclosure encaja con `SKILL.md` + referencias cargadas bajo demanda.

La implementación debe volver a verificar la documentación actual de skills.sh antes de publicar, porque es un servicio externo y puede evolucionar.
