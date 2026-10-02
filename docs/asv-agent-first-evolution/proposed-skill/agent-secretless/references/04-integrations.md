# Integraciones

Esta referencia no es un catálogo de comandos hardcodeados. Sirve para mapear intención del usuario a familias de capabilities.

## GitHub

Intenciones típicas:

- leer issue → `github.issue.read`;
- crear issue → `github.issue.create`;
- crear release → `github.release.create`.

Sólo ejecuta si discovery/respuesta actual anuncia la relación correspondiente.

## PostgreSQL

- conexión → `postgres.connect`;
- query → `postgres.query`.

El destino autorizado lo decide la configuración/broker. No cambies host/address para sortear una denegación.

## SSH/Git SSH

Busca la capability/rel de sesión/signing anunciada. La clave privada nunca debe materializarse en el proceso del agente.

## Otras integraciones

No extrapoles nombres. Si ASV no anuncia una relación, considérala unsupported para esa instalación.
