# Riesgos y preguntas abiertas

## R1 — Convertir HATEOAS en un workflow engine

**Riesgo:** introducir estado, transiciones, contexto y planificación dentro de ASV demasiado pronto.

**Control:** v1 sólo devuelve links por respuesta. No `agent next` stateful.

## R2 — Duplicar autorización en capabilities

**Riesgo:** un `available=true` se interpreta como “permitido”.

**Control:** distinguir existencia/configuración de autorización; Cedar siempre evalúa la petición real.

## R3 — Command injection vía links

**Riesgo:** devolver cadenas shell e invitar al agente a ejecutarlas.

**Control:** `program` + `argv[]`; prohibir `sh -c` como contrato normal.

## R4 — Skill demasiado grande

**Riesgo:** meter todo ASV en contexto.

**Control:** router corto + referencias bajo demanda; dividir sólo con evidencia.

## R5 — Skill y schema divergen

**Control:** metadata de schema soportado + eval mismatch + versionado.

## R6 — Setup adquiere demasiadas responsabilidades

**Riesgo:** convertirse en instalador, migrador, vault manager y policy editor.

**Control:** setup prepara runtime; operaciones destructivas/sensibles siguen comandos explícitos.

## R7 — Package-manager ownership

**Riesgo:** `asv update` pisa archivos gestionados por mise/apt/rpm.

**Control:** detectar `installed_via`; delegar actualización al propietario de instalación.

## R8 — Servicio apunta a versión antigua tras upgrade mise

**Control:** `asv setup` reescribe/verifica el ExecStart de su propia instalación; `doctor` compara paths y versiones.

## R9 — Descubrimiento anuncia feature incompleta

Especialmente relevante para approval/audit/TPM/OAuth2.

**Control:** capabilities derivadas del runtime; no del roadmap o de tipos que existan pero no tengan ruta completa.

## R10 — Exposición de metadata sensible

Aunque no sea secret material, nombres de hosts/credenciales pueden revelar topología.

**Control:** discovery general devuelve capabilities, no inventario detallado. Los listados específicos siguen controles existentes y redacción apropiada.

## Pregunta futura Q1 — `asv agent next`

Sólo investigar si los AAT muestran que un agente no puede navegar de forma robusta con links locales.

## Pregunta futura Q2 — MCP

El roadmap menciona MCP opcional. No añadirlo hasta que el contrato agent-facing CLI sea estable; después puede ser otra proyección del mismo ADT, no un segundo vocabulario.

## Pregunta futura Q3 — Split de skills

Evaluar tras datos de uso/evals. Evitar crear tres o cuatro skills públicas sólo por organización interna.

## Pregunta futura Q4 — Socket activation

Buena evolución posterior de UX/lifecycle, pero no requisito de M13-DX. Primero hacer estable `setup` + user service.

## Pregunta futura Q5 — GUI installation

Mantener separada. La GUI puede consumir el broker/control plane, pero no debe condicionar el contrato agent-first.
