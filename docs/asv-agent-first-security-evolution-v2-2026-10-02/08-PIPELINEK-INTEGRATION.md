# Integración ASV ↔ PipelineK

> **No-overlap law:** PipelineK owns durable orchestration and `core.sh`; ASV owns authority and credential semantics; `pipelinek-asv` is only an adapter. `asv-brokerd` never depends on PipelineK.

## 1. Principio central

```text
PipelineK = autoridad de orquestación durable
ASV       = autoridad de identidad/credencial/policy
Agent     = intención
```

La integración debe conservar estas fronteras.

## 2. Restricción no negociable sobre PipelineK

La integración se implementa como:

```text
pipelinek-asv
Delivery = OFFICIAL_PLUGIN
```

No como cambio semántico del core.

### Core PipelineK puede crecer sólo con

- interfaces;
- ports;
- capabilities;
- metadata;
- mecanismos genéricos de SDK;

cuando exista una necesidad genérica y no ASV-specific.

### Core PipelineK no recibe

```text
AsvClient
AsvSession
Cedar
Vault
Surrogate
ASV-specific coordinator branch
ASV-specific compiler path
```

## 3. Jenkins-friendly permanece intacto

No modificar firmas ni semántica de:

```text
sh(...)
withCredentials(...)
retry(...)
timeout(...)
dir(...)
withEnv(...)
...
```

La extensión ASV es explícitamente PipelineK-native.

## 4. Integración principal con `sh`

ASV debe integrarse **alrededor** del `sh` existente.

```kotlin
asv.authorized(
    operation = "npm.package.publish",
    resource = "@rubentxu/foo",
    minimumPosture = STRONG_SECRETLESS,
) {
    sh("npm publish")
}
```

Flujo:

```text
asv.authorized plugin Step
   ↓
prepare ASV authority
   ↓
BodyContinuation
   ↓
ExecutionContextPatch.Environment / safe handles
   ↓
core.sh unchanged
   ↓
tool
```

No crear:

```text
asvExec
safeSh
core.exec ASV
```

## 5. Por qué `sh` es el puente correcto

El trabajo agentic real usa CLI.

Mantener:

```text
normal shell command
```

permite aprovechar:

- durable execution;
- timeout;
- cancellation;
- replay/reconciliation;
- output capture;
- sandbox;
- workspace semantics;
- event model;

sin duplicar nada.

## 6. Qué puede proyectar el plugin

Sólo material no secreto cuando exista estrategia fuerte:

```text
SSH_AUTH_SOCK
proxy endpoint
surrogate config path
ASV session handle
dynamic credential helper endpoint
NPM_CONFIG_USERCONFIG pointing to surrogate config
```

Si el target requiere el secreto real, la postura debe degradarse explícitamente y, preferiblemente, usar isolated worker.

## 7. SDK pressure test

V1 debe intentar resolverse con mecanismos existentes:

```text
BodyExecutionOwner.HANDLER_CONTINUATION
BODY_CONTINUATION_CAPABILITY
BodyInvocationContext
ExecutionContextPatch.Environment
StepDefinitionContributor
DirectiveContributor
```

Si falta algo:

1. describir la capability genérica ausente;
2. demostrar segundo consumidor;
3. diseñarla en PipelineK SDK;
4. certificarla independientemente;
5. consumirla desde `pipelinek-asv`.

## 8. Capability genérica candidata: ExecutionIdentity

No implementarla de antemano.

Si es necesaria para plan-bound authorization, podría tener forma:

```text
runId
step identity
input digest/fingerprint
attempt
plugin release digest
```

Consumidores potenciales:

- ASV;
- signing;
- provenance;
- attestation;
- remote execution;
- audit;
- locks.

Nunca llamarla `ASV_*`.

## 9. DSL del plugin

Ejemplos:

```kotlin
asv.authorized(...)
asv.verifyPosture(...)
asv.rotation(...)
```

Directivas sólo para policy/config declarativa:

```kotlin
directives {
    asvPolicy(
        minimumPosture = STRONG_SECRETLESS
    )
}
```

No ejecutar secretos desde una directive.

## 10. Steps semánticos

Para operaciones donde evitar shell aporte seguridad real:

```text
asv.github.release
asv.credential.rotate.*
asv.certificate.rotate.*
```

No crear un Step por cada CLI existente.

Regla:

```text
tool normal + secretless adapter => authorized { sh(...) }
high-value semantic API          => semantic Step
```

## 11. ASV → PipelineK

`asv-brokerd` nunca lanza PipelineK.

Flujo:

```text
asv CLI/control plane
   ↓
AutomationPort
   ↓
PipelineKAutomation adapter
   ↓
PipelineK
   ↓
pipelinek-asv plugin
   ↓
ASV atomic operations
```

PipelineK recibe refs y receipts, no secret bytes.

## 12. Versionado

```text
PipelineK Plugin API
pipelinek-asv plugin
ASV protocol
```

Versionados independientemente.

Manifest conceptual:

```yaml
requires:
  pipelinekPluginApi: ">=1 <2"
  asvProtocol: ">=7 <9"
```

## 13. Gate arquitectónico

Eliminar `pipelinek-asv` debe dejar PipelineK equivalente funcionalmente:

```text
core build
core tests
Jenkins DSL
runtime
```

ASV integration is removable.
