# Research directions y criterios de adopción

## 1. Criterio

Adoptar una tecnología sólo si mejora al menos una dimensión:

1. menos secreto persistente;
2. menos secreto dentro del proceso agente;
3. autoridad más corta/atenuada;
4. mejor identidad/atribución;
5. mejor resistencia a host/runtime;
6. mejor automatización/recovery;
7. mejor evidencia.

## 2. Líneas prioritarias

### OAuth/OIDC federation

Usar cuando el proveedor real permita sustituir client secrets/tokens persistentes.

### Proof-of-possession

DPoP/mTLS/signer-backed cuando exista soporte real.

### SPIFFE/SPIRE-like workload identity

Adapter útil en infra con identidad de workload.

### Transaction/agent identity protocols

Seguir evolución IETF sobre transaction tokens/workload identity/delegation. No congelar un Internet-Draft como wire contract ASV hasta madurez suficiente.

### TUF / SLSA

Aplicables al updater y provenance de release.

### WebAuthn/FIDO

Human gate criptográfico para efectos sensibles.

### Keylime / TPM / IMA

Remote/measured attestation.

### Trustee / Confidential Containers

Preferible a inventar KBS propio para confidential workers.

### Intel TDX / AMD SEV-SNP

Valor alto en worker/broker remoto; prioridad menor para workstation local.

### SELinux / fapolicyd / fs-verity

Defense-in-depth enterprise y tool identity.

### OpenTelemetry

Agent/workflow/security observability con redacción estricta.

### Agent runtime control standards

Integrar ASV como enforcement point, no replicar un agent framework.

## 3. GO/NO-GO template

Para cualquier spike:

```text
Problem:
Security property:
Threat reduced:
Threat NOT reduced:
Required dependencies:
Failure mode:
Fallback:
Performance cost:
Operational cost:
Agent UX:
Evidence:
GO / NO-GO:
```

## 4. Rechazos preventivos

- generic memory patching para inyectar secrets;
- eBPF como mecanismo mágico de “secretless” sin prueba;
- custom PQ crypto;
- self-declared agent identity;
- config temporal etiquetada automáticamente como strong-secretless;
- bearer tokens largos cuando existe federation real;
- workflow logic creciente dentro de broker;
- “AI policy engine” no determinista dentro de authorization path.
