# ADR — CLI hipermedia/autodescubrible para agentes

**Estado propuesto:** Accepted para el evolutivo

## Contexto

ASV es agent-first pero la CLI actual está diseñada principalmente para lectura humana. Una skill que codifique secuencias completas de comandos duplicaría el conocimiento del runtime, se quedaría obsoleta y trasladaría decisiones deterministas al LLM.

Se busca el beneficio de HATEOAS: el cliente conoce una entrada y navega por acciones que el servidor/runtime anuncia como disponibles.

## Opciones consideradas

### A. Documentar todos los comandos en la skill

Ventaja: cero cambios de código.

Problemas:

- drift entre skill y CLI;
- el agente inventa recovery paths;
- cambios de comando exigen republicar conocimiento;
- no refleja capabilities reales de cada host.

**Rechazada.**

### B. Crear una API HTTP local HATEOAS

Ventaja: semántica REST convencional.

Problemas:

- nuevo listener y superficie de ataque;
- duplicación del IPC;
- más lifecycle/configuración;
- aporta poco a un producto shell-first.

**Rechazada para este evolutivo.**

### C. CLI JSON con relaciones semánticas y `invoke` argv

Ventajas:

- mantiene shell-first;
- reutiliza el binario público;
- fácil de consumir por agentes;
- no requiere shell interpolation;
- permite progressive disclosure;
- refleja runtime real.

**Elegida.**

### D. Motor stateful `asv agent next`

Puede ser útil más adelante, pero convierte el evolutivo en un orquestador y obliga a estabilizar un modelo de workflow antes de necesitarlo.

**Diferida.**

## Decisión

Añadir `asv agent discover --json` y un envelope común para respuestas agent-facing.

Cada respuesta publica `links[]` con relaciones tipadas y descriptores de invocación.

Entrada conocida:

```bash
asv agent discover --json
```

El agente sólo puede asumir esa entrada y el schema v1. El resto debe descubrirlo.

## Forma del link

```json
{
  "rel": "asv://rels/doctor",
  "operation": "system.doctor",
  "invoke": {
    "program": "asv",
    "argv": ["doctor", "--json"]
  },
  "safety": "read-only",
  "requires_human": false
}
```

### Regla de ejecución

`invoke.program` y `invoke.argv` se ejecutan mediante APIs de proceso directas. No se concatenan en una cadena ni se entregan a `sh -c`.

## Semántica de disponibilidad

Un link puede significar:

- la operación existe;
- la instalación actual la soporta;
- tiene sentido en el estado actual.

No significa:

- que Cedar la vaya a permitir;
- que el usuario haya aprobado;
- que la operación vaya a tener éxito.

## Consecuencias

### Positivas

- skill mucho más pequeña;
- menor drift;
- recuperación guiada;
- mejor testing de superficies agent-first;
- fácil compatibilidad con múltiples agentes.

### Costes

- se introduce un schema público;
- hay que versionar relations/operations;
- se necesitan contract tests;
- la CLI debe separar rendering humano y rendering JSON.

## Compatibilidad

Añadir `--json` y `agent discover` es aditivo. Los comandos humanos existentes continúan.

Cambios incompatibles del schema incrementan `schema` major. Campos opcionales nuevos no requieren major.
