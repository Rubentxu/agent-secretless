# Approvals y audit

## Approvals

Un human gate no es un error a resolver automáticamente.

Si la respuesta contiene:

```json
{"requires_human": true}
```

la ejecución agentic se detiene.

No uses otro socket, proceso, policy file o credential para autoaprobar.

No asumas que `approval.request` existe sólo porque el policy engine tenga tipos de approval. El runtime debe anunciar una ruta segura.

## Audit

Sólo solicita audit si existe la relación correspondiente.

Nunca busques secretos en audit/logs. El objetivo es evidencia de operación, resultado y postura, no material sensible.
