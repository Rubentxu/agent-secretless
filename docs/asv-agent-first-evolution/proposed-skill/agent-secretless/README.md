# agent-secretless — propuesta (retirada, 2026-10-04)

**Este directorio ya no contiene la skill. La skill vive en
[`Rubentxu/agent-skill/skills/agent-secretless`](https://github.com/Rubentxu/agent-skill/tree/main/skills/agent-secretless),
publicada en el commit `1778767`.**

ADR-05 lo decidió y el contrato lo hace cumplir: *«no se mete en el repo de ASV
como fuente canónica ni dentro del binario»*. Mantener aquí una copia completa
sería una segunda autoridad que deriva, y esta copia ya había derivado — la
propuesta original fallaba 27 de las 93 comprobaciones de
`tests/skill_contract.py`, todas por no coincidir con el producto:

- el frontmatter declaraba el schema `1` donde el runtime sirve `asv.agent/v1`;
- no nombraba ninguna de las seis relaciones publicadas, ni ninguno de los cinco
  códigos de `error.code`, ni los ocho campos del sobre;
- la tabla de modos usaba backticks donde el guard exige enlaces markdown;
- un bloque del anti-patrones quedaba sin negación y se leía como instrucción
  de retrieval.

Todo eso se corrigió **antes** de publicar, contrastando con el CLI real
(`asv agent discover --json`) y no con la especificación. El contenido
publicado no es el que estaba aquí.

## Por qué no se publica esta copia

`tests/skill_contract.py` se niega a ejecutarse contra cualquier ruta dentro de
este repositorio, y sale con error en vez de con un skip. Una suite apuntada al
borrador daría verde entero, y ese verde no significaría nada: la copia que
instala un agente es la del otro repositorio, y ésa es la que se desincroniza.

Para verificarla:

```bash
git clone --depth 1 https://github.com/Rubentxu/agent-skill.git ../agent-skill
python3 tests/skill_contract.py        # 98 comprobaciones contra la copia publicada
```

El contenido retirado sigue en el historial de este repositorio y en el
repositorio público.
