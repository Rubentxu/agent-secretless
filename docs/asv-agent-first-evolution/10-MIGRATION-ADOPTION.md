# Migración y adopción

## 1. Compatibilidad hacia atrás

Los comandos existentes mantienen su forma humana.

El cambio principal es aditivo:

```text
+ asv setup
+ asv doctor
+ asv agent discover --json
+ --json en superficies seleccionadas
```

No renombrar comandos existentes como parte de este evolutivo salvo que exista una razón independiente.

## 2. Migración del packaging

### Antes

Riesgo típico:

```text
build workspace
copy target/release/asv*
```

### Después

```text
read product manifest
build declared targets
stage declared files
assert no undeclared executable
sign/package
```

`asv-vault-tool` continúa disponible en entorno de desarrollo/harness.

## 3. Migración del usuario

No exigir que usuarios existentes reinstalen inmediatamente si ya operan el broker manualmente.

`asv doctor` debe poder detectar instalación legacy y mostrar una ruta segura de adopción.

Ejemplo conceptual:

```text
Installation: legacy/manual
Broker: healthy
Recommendation: run `asv setup` to register managed user service
```

No mover vaults automáticamente sin una migración diseñada y probada.

## 4. Migración de agentes

### Antes

Un agente puede conocer comandos de memoria/documentación.

### Después

La skill instruye:

1. comprobar `asv`;
2. ejecutar `asv agent discover --json`;
3. validar schema;
4. seguir relaciones;
5. detenerse en human gates.

Los agentes no necesitan conocer `asv-brokerd`.

## 5. Adopción en `Rubentxu/agent-skill`

Secuencia recomendada:

```text
1. Implementar DX2 en ASV.
2. Congelar ejemplos JSON con tests.
3. Publicar/actualizar skills/agent-secretless en Rubentxu/agent-skill.
4. Ejecutar scripts/validate_skills.py.
5. Añadir evals al CI afectado.
6. Instalar selectivamente con npx skills add.
7. Fusionar/publicar.
8. Verificar indexación en skills.sh por separado.
```

> **Los pasos 3 a 7 están ejecutados** (2026-10-04, commit `1778767` en
> `Rubentxu/agent-skill`). El borrador ya no se copia desde este repositorio:
> `tests/skill_contract.py` verifica la copia publicada, y falla si no la
> encuentra. Queda pendiente sólo el paso 8, que depende de un índice externo.

## 6. Prompt corto para un agente implementador

```text
Adopta el paquete M13-DX como evolutivo incremental del roadmap actual.
No reescribas el broker ni crees un workflow engine. Mantén `asv` como única
interfaz pública y `asv-brokerd` como runtime privado. Implementa por orden
DX0→DX4, con tests rojos discriminantes antes de cada cambio de comportamiento.
La CLI agent-facing debe exponer `asv.agent/v1` y relaciones tipadas; no uses
strings shell ejecutables ni dupliques Cedar. Publica la skill sólo después de
que el contrato CLI esté probado. Testing quirúrgico durante desarrollo y suite
completa + adversarial + distribution AAT en integración/release. Commits
atómicos Conventional Commits y no declares un hito completado sin su exit test.
```

## 7. Actualización de documentación

Cuando se implemente:

- añadir M13-DX al roadmap authority;
- actualizar quick start para instalación publicada, no `cargo build` como experiencia principal;
- documentar CLI agent schema;
- documentar clasificación de binarios;
- enlazar skill oficial desde README sin hacerla requisito del core.
