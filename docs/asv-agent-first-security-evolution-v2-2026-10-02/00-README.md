# ASV — Agent-First Security Evolution Pack v2

**Proyecto:** `Rubentxu/agent-secretless`  
**Baseline revisado:** `main@39ae8fbafbee6a3114baa6f431ed56f928ca6984`  
**Roadmap autoridad:** `agent-secretless-vault-spec/docs/15-ROADMAP.md`  
**Propósito:** evolución aditiva y continuista de ASV, reconciliada para evitar solapes con el roadmap actual, PipelineK y las skills.

## Regla de autoridad

Este paquete no reemplaza M0–M13 ni corrige hechos por intención.

Se preserva:

- M9 estaba parcialmente abierto en este baseline y **quedó cerrado en
  `v0.28.0`** (2026-10-03): la fila exit-UAT de
  `16-SECURITY-RELEASE-GATES.md` pasa de **NOT MET** a **MET** y la
  cobertura UAT de 28/40 a 29/40. Lo que ese cierre *no* afirma sigue en
  pie, y conviene no perderlo al leer "cerrado": `relay_substituted` no
  tiene listener de producción, se sirve una petición por túnel, y el nonce
  derivado del destino impide trasladar una prueba a otro destino pero no
  da frescura.
- M11 no está cerrado sin proveedor OAuth2 real y evidencia contra un AS real.
- M12 no está cerrado sin evidencia sobre TPM hardware real.
- M13 sigue siendo el gate RC/v1.0.

La parte mínima de distribución y descubrimiento agent-first ya no se trata como un nuevo M14: entra como **M13-DX**, subdivisión de M13. Tras v1.0, la continuidad propuesta es M14–M18.

## Ley de no duplicación

Cada capacidad tiene un único dueño semántico:

```text
ASV
  identidad · autoridad · credenciales · policy · posture
  adapters de tooling · rotación semántica · attestation

PipelineK
  Steps · core.sh · ejecución durable · journal · replay
  cancelación · reconciliación · workflows

pipelinek-asv
  adaptación entre contratos, sin autoridad propia

Skills
  discovery + routing, sin lógica de runtime
```

La composición entre restricciones es por intersección, nunca por unión.

## Secuencia consolidada

```text
M0-M12 existentes
   ↓
M13 + M13-DX
   ↓
v1.0
   ↓
M14 Credential Workflow Adapters
   ↓
M15 Authority Planning + Plan-Bound Execution
   ↓
 ┌───────────────┬────────────────┐
 ↓               ↓                │
M16 Durable      M17 Attested     │
Automation       Authority        │
 └───────────────┴────────────────┘
                 ↓
           M18 v1.1 stabilization
```

## Invariantes

1. No existe API agent-facing de recuperación de secretos.
2. El broker conserva la autoridad sobre material secreto.
3. Se prefiere eliminar el secreto persistente a transportarlo mejor.
4. Una proyección con secreto legible por el proceso objetivo nunca se etiqueta `STRONG_SECRETLESS`.
5. M11 sigue siendo dueño de OAuth/STS/mTLS/provider mechanisms.
6. M7/M12 siguen siendo dueños del hardening y TPM; M17 consume evidencias, no los reimplementa.
7. ASV no incorpora un workflow engine durable: delega operaciones complejas mediante `AutomationPort`.
8. `asv-brokerd` nunca depende de PipelineK.
9. Las skills viven fuera del binario y siguen relaciones anunciadas por ASV.
10. TDX/SNP son investigación condicional para deployments remotos/confidenciales, no dependencia de la línea local.

## Lectura

1. `12-CAPABILITY-OWNERSHIP-AND-NO-OVERLAP.md`
2. `01-PRODUCT-EVOLUTION-SPEC.md`
3. `02-ARCHITECTURE.md`
4. `03-AGENT-HYPERMEDIA-CLI.md`
5. `04-CREDENTIAL-WORKFLOW-ADAPTERS.md`
6. `05-IDENTITY-AUTHORITY-PLAN-BOUND.md`
7. `06-ATTESTATION-TRUSTED-EXECUTION.md`
8. `07-DISTRIBUTION-AND-SKILLS.md`
9. `08-PIPELINEK-INTEGRATION.md`
10. `09-ROTATION-AND-AUTOMATION.md`
11. `roadmap/20-ROADMAP-CONTINUATION.md`
12. `roadmap/31-WORK-UNITS.md`
13. `aat/30-AAT-UAT-MATRIX.md`
