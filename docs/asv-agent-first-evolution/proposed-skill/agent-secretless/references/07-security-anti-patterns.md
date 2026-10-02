# Anti-patrones de seguridad

No hacer:

```text
export GITHUB_TOKEN=<real>
export AWS_SECRET_ACCESS_KEY=<real>
asv ... --secret <real>
cat vault-file
strings /proc/<pid>/mem
grep TOKEN ~/.config
```

No convertir un surrogate en “secreto seguro de imprimir”. Aunque no tenga autoridad remota, sigue siendo material de sesión y debe tratarse con redacción apropiada.

No interpretar `available` como `authorized`.

No responder a una denegación cambiando el destino, identity, socket o policy para sortearla.

No atribuir garantías de TPM, OAuth2, hardening o connectors por existir tipos/tests; usa el estado/capabilities del runtime actual.
