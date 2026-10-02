# Instalación y setup

## Regla

El usuario/agente opera `asv`; no administra `asv-brokerd` como una herramienta pública.

## Si `asv` no existe

Usa el mecanismo oficial que el usuario haya elegido. No inventes URLs ni descargues artefactos no verificados.

Tras instalar:

```bash
asv setup
asv doctor --json
```

## Si ASV ya existe

Empieza por discovery. Sigue `setup` sólo cuando el runtime lo anuncie o el usuario lo pida.

## Idempotencia

Repetir setup no debe destruir/recrear vaults ni secretos. Ante cualquier migración sensible, exige la ruta explícita que ASV publique.
