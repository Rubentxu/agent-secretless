# Especificación de evolución de producto

## 1. Problema

Los agentes operan principalmente mediante CLI y shell. El patrón tradicional sigue siendo:

```bash
TOKEN=...
export TOKEN
tool ...
```

o:

```text
~/.npmrc
~/.m2/settings.xml
~/.gradle/gradle.properties
~/.netrc
~/.pypirc
...
```

Eso expone credenciales a:

- entorno;
- argv;
- logs;
- tracing de herramientas;
- ficheros persistentes;
- procesos hijos;
- plugins;
- dumps;
- memoria del proceso;
- prompt/tool traces.

ASV ya resuelve parte del problema mediante broker, policy, signer/proxy y aislamiento. El siguiente paso es convertir la seguridad en un **protocolo de uso de autoridad**, no en un mero almacenamiento de bytes.

## 2. Objetivo de producto

El agente expresa:

```text
QUIERO realizar <operation>
SOBRE <resource>
CON <minimum posture>
```

ASV determina:

```text
qué identidad
qué credencial
qué estrategia
qué audience
qué approval
qué runtime posture
qué evidencia
```

El agente no decide cómo transportar el secreto.

## 3. Invariantes

### EV-P01 — No secret retrieval

Ninguna superficie agent-facing devuelve material secreto.

### EV-P02 — Preferir eliminar el secreto

Si el proveedor ofrece una forma de no mantener un secreto estático, ASV debe preferirla.

Orden conceptual:

```text
Native federation
  >
Proof-of-possession / brokered signer
  >
Dynamic short-lived credential
  >
Semantic proxy / credential helper
  >
Ephemeral projection
  >
Isolated process exposure
  >
Raw process exposure
  >
Unsupported
```

La selección real depende de compatibilidad y policy.

### EV-P03 — Degradación explícita

`ConfigOverlay` o un fichero efímero **no** implican secretless si el target process puede leer el secreto.

Posturas existentes permanecen autoridad:

```text
STRONG_SECRETLESS
SHORT_LIVED_EXPOSURE
ISOLATED_PROCESS_EXPOSURE
RAW_PROCESS_EXPOSURE
UNSUPPORTED
```

### EV-P04 — Intención antes de autoridad

Una operación sensible debe poder describirse como `ActionIntent` antes de prestar autoridad.

### EV-P05 — Plan inmutable

Una autorización puede quedar ligada a un digest que incluya:

- operación;
- recurso;
- destino;
- tool identity;
- argumentos relevantes;
- config fingerprint;
- principal;
- agente;
- policy version;
- expiración.

Si cambia una dimensión ligada al plan, la autorización deja de ser válida.

### EV-P06 — Human gate en la frontera de impacto

Las aprobaciones no deben interrumpir trabajo seguro innecesariamente. Se colocan antes de efectos irreversibles o de alto impacto.

### EV-P07 — Skills como navegación

Las skills no replican workflows de ASV. Describen cómo descubrir y seguir affordances publicadas por ASV.

### EV-P08 — Automation fuera del broker

Los workflows complejos pueden delegarse a PipelineK. `asv-brokerd` no depende de PipelineK.

## 4. Jerarquía de estrategia de credencial

```rust
enum CredentialStrategy {
    NativeFederation,
    ProofOfPossession,
    BrokeredSigner,
    DynamicCredential,
    SemanticProxy,
    CredentialHelper,
    SurrogateProxy,
    EphemeralProjection,
    IsolatedProcessExposure,
    RawCredentialExposure,
}
```

No es obligatorio usar exactamente este enum; sí conservar el modelo cerrado y la comparación explícita de postura.

## 5. Consumidores

### Agente

Necesita:

- descubrir qué puede hacer;
- ejecutar sin ver secretos;
- recibir errores accionables;
- seguir `next actions`;
- detenerse ante approval/policy;
- no tener que conocer internals.

### Humano operador

Necesita:

- política;
- enrolment;
- approvals;
- rotación;
- postura;
- auditoría;
- diagnóstico.

### Tooling

Necesita:

- socket;
- proxy;
- signer;
- config overlay;
- dynamic credential;
- federation token;
- helper.

### Automatizador

Necesita:

- operaciones ASV atómicas;
- idempotency keys;
- referencias opacas;
- receipts;
- estados typed.

## 6. Superficies

```text
asv CLI            public human + agent entry
asv agent          machine-friendly discovery/control
asv-brokerd        secret-bearing data/control plane
asv-console        optional human GUI
MCP adapter        optional agent surface
pipelinek-asv      optional official automation plugin
skills             external agent navigation layer
```

## 7. Límites de confianza

El producto debe distinguir siempre:

```text
Human principal
Agent actor
Workload identity
Tool identity
Session identity
Credential authority
Host/runtime posture
```

No colapsar todo a UID/PID.

## 8. Resultado deseado

Ejemplo:

```text
Usuario: publica el paquete

Agent:
  intenta npm.package.publish

ASV:
  identifica agente/workload
  descubre una estrategia fuerte disponible
  crea ActionIntent
  liga plan a registry/package/tool
  aplica policy
  obtiene short-lived/federated authority
  ejecuta o prepara el uso
  produce receipt

El agente nunca ve NPM_TOKEN.
```
