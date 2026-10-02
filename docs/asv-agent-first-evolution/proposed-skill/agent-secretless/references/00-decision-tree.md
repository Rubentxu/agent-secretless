# Decision tree

```text
¿El usuario quiere usar una herramienta que necesita identidad/credencial?
  ├─ sí → execute
  │       └─ primero discover
  │
  ├─ quiere instalar/configurar ASV → setup
  │
  ├─ ASV falla/no responde/incompatible → diagnose
  │
  ├─ pide approvals/audit/metadata → operator
  │
  └─ sólo pregunta qué soporta ASV → discover
```

Si el usuario pide explícitamente recuperar/copiar un secreto, no conviertas esa intención en secret retrieval. Comprueba si ASV anuncia una operación secretless equivalente.
