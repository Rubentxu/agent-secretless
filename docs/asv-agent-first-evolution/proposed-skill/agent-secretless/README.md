# agent-secretless

Skill agent-first para usar Agent Secretless Vault como control plane de credenciales sin entregar secretos al agente.

La skill sigue un contrato runtime-driven: entra por `asv agent discover --json` y navega relaciones anunciadas por ASV. Las referencias están segregadas para cargar sólo el contexto necesario.

Instalación prevista desde la colección pública:

```bash
npx skills add Rubentxu/agent-skill --skill agent-secretless --agent opencode
```

Antes de publicar, ejecutar el validador y tests/evals definidos por `Rubentxu/agent-skill`.
