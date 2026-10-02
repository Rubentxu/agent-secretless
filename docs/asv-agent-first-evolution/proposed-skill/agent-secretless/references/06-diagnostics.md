# Diagnóstico

## Prioridad

1. seguir un link `doctor` anunciado;
2. `asv doctor --json` cuando sea parte del contrato soportado;
3. clasificar el resultado;
4. no saltar a inspeccionar internals sensibles.

## Clases comunes

- broker unavailable;
- setup required;
- CLI/broker version mismatch;
- agent schema mismatch;
- capability unavailable;
- configuration blocked;
- human approval required;
- degraded hardening.

## Prohibido

- leer vault directamente;
- imprimir environment completo;
- buscar tokens en procesos;
- iniciar binarios privados manualmente para “probar suerte”;
- rebajar una policy para obtener verde.
