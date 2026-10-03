# Atestación, trusted execution y defensa en profundidad

> **Ownership note:** M17 consumes hardening and hardware evidence from M7/M12. It does not replace TPM sealing, Landlock, seccomp, cgroups or the existing Linux hardening layer.

## 1. Objetivo

La atestación no sustituye a policy ni a identidad. Añade una pregunta:

```text
¿confío suficientemente en el entorno actual para liberar esta autoridad?
```

## 2. Attestation as policy input

```text
request
  ↓
identity
  ↓
policy
  ↓
attestation?
  ↓
credential strategy
  ↓
use
```

Ejemplo:

```text
permit if:
  operation == production.deploy
  AND agent == expected
  AND destination == approved
  AND attestation == trusted
  AND evidence_age < 60s
```

## 3. AttestationPort

El dominio consume:

```text
Trusted
Untrusted
Stale
Unsupported
```

No consume directamente APIs Intel/TPM/Keylime.

## 4. TPM / measured boot / IMA / Keylime

Roles conceptuales:

```text
TPM           raíz de confianza
Measured Boot qué arrancó
IMA           qué se carga/cambia
Keylime       verificación remota/continua
ASV           decisión de prestar autoridad
```

Primer objetivo útil:

```text
Attested Secret Release
```

No “soportar Keylime” por checklist.

## 5. Confidential Computing

### Intel TDX

Útil principalmente para:

- broker remoto;
- worker de compatibilidad;
- shared enterprise credential service;
- ejecución con operador de host no confiable.

Menor prioridad para workstation local de un único usuario.

### Otros TEEs

No ligar el modelo a Intel.

Adapters futuros:

```text
TDX
AMD SEV-SNP
Confidential Containers / Trustee
other attested environments
```

## 6. Trustee/Key Broker

Preferir integración con ecosistemas existentes para key-release.

Patrón:

```text
workload starts
  ↓
attestation
  ↓
trusted?
  ├─ no  -> vault/KEK locked
  └─ yes -> release wrapped key / authority
```

ASV no debe construir su propio KBS salvo necesidad demostrada.

## 7. SELinux

Para Linux enterprise:

```text
asv_cli_t
asv_broker_t
asv_vault_t
```

Usar junto con:

```text
seccomp
Landlock
cgroup
ptrace restrictions
```

No sustituirlos.

## 8. fapolicyd / fs-verity / IMA

Objetivo:

```text
¿el binario al que voy a prestar autoridad es confiable e inmutable?
```

Posibles señales:

- digest;
- fs-verity;
- package trust;
- IMA appraisal;
- fapolicyd state.

Integrarlo como `ToolTrustEvidence`, no como dependencia del dominio.

## 9. OpenSCAP

Uso recomendado:

```text
posture evidence
```

No motor de autorización interno.

`asv doctor --security --json` puede proyectar estado de compliance sin duplicar OpenSCAP.

## 10. PQC

No implementar algoritmos propios.

ASV debe:

- consumir capacidades del stack TLS/SSH;
- exponer diagnóstico;
- permitir policy si existe necesidad enterprise;
- evitar prometer “quantum safe” por una única primitive.

## 11. Prioridad

Orden recomendado:

1. TPM real / hardware-backed key path.
2. AttestationPort.
3. Keylime/Trustee adapter.
4. policy gating.
5. confidential worker.
6. remote broker in TEE.

TDX no debe retrasar adapters de tooling ni agent UX.
