# Discovery e hipermedia

## Entrada

```bash
asv agent discover --json
```

## Comprobar

1. `schema` compatible con `asv.agent/v1`.
2. `status`.
3. `data.capabilities` si está presente.
4. `links`.

## Selección

Escoge por `rel`/`operation`, no por texto de `description`.

Nunca asumas que una capability documentada existe en esta máquina. El runtime manda.

## Ejecución

Un `invoke` se ejecuta como proceso + argv. No concatenes una shell.

Si la operación necesita argumentos del usuario, añádelos como elementos argv después de validar que corresponden al contrato del comando.

## Stop conditions

- schema desconocido;
- `requires_human=true`;
- relation ausente;
- estado `blocked` sin recovery link;
- runtime informa incompatibilidad.
