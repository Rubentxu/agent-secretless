# ADR — Skills externas, autocontenidas y guiadas por runtime

**Estado propuesto:** Accepted

## Contexto

`Rubentxu/agent-skill` ya sigue un patrón sano:

- `skills/<slug>/SKILL.md`;
- frontmatter con `name` y `description`;
- referencias locales;
- tests/evals;
- cada skill autocontenida;
- validador que comprueba rutas y manifiesto.

skills.sh descubre skills válidas a partir de sus `SKILL.md`, y el CLI permite instalación selectiva desde el repositorio.

## Decisión

Crear inicialmente una única skill pública:

```text
skills/agent-secretless/
```

No se mete en el repo de ASV como fuente canónica ni dentro del binario. Vive en `Rubentxu/agent-skill`.

## Por qué una skill inicial y no muchas

El requisito de segregación se resuelve mediante progressive disclosure interno (`references/`) sin multiplicar superficies públicas antes de tener evidencia.

Ventajas:

- una única activación obvia en skills.sh;
- instalación simple;
- no hay dependencias entre skills;
- menor riesgo de que sólo se instale una mitad del workflow;
- el router sigue siendo muy pequeño.

Se divide más adelante sólo si evals demuestran bloat o activaciones incorrectas.

## Responsabilidad de la skill

La skill responde a:

- cuándo usar ASV;
- cómo comprobar que está instalado;
- cómo entrar por `asv agent discover --json`;
- cómo seguir `links`;
- cuándo detenerse;
- qué anti-patrones están prohibidos;
- cómo reportar evidencia.

No responde a:

- cómo abrir el vault internamente;
- cómo funciona Cedar;
- cómo extraer un secreto;
- cómo autoaprobar;
- cómo inventar un comando no anunciado.

## Router por intención

`SKILL.md` clasifica la intención en cinco modos:

1. `discover` — saber qué puede hacer la instalación;
2. `setup` — instalar/bootstrap/health;
3. `execute` — ejecutar trabajo secretless;
4. `diagnose` — recuperar errores y degradación;
5. `operator` — metadata, approvals, audit y tareas humanas.

Cada modo carga sólo una o dos referencias.

## Compatibilidad

La skill declara su propia versión y el rango de `asv.agent` schema soportado.

Ejemplo conceptual:

```yaml
metadata:
  version: "0.1.0"
  asv-agent-schema: "1"
```

La skill siempre valida el `schema` recibido antes de seguir links.

## Publicación

Validaciones mínimas:

```bash
python3 scripts/validate_skills.py
npx skills add Rubentxu/agent-skill --list
npx skills add Rubentxu/agent-skill --skill agent-secretless --agent opencode
```

La indexación en skills.sh es una verificación independiente posterior.

## Evolución futura

Sólo con evidencia se considerará:

```text
agent-secretless-use
agent-secretless-admin
agent-secretless-audit
```

Cada una tendría que ser autocontenida y no depender de leer ficheros de otra skill.
