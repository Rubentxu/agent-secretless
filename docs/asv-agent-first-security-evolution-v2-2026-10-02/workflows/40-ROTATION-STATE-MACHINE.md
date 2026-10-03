# Rotation state machine

```text
PLANNED
  |
  v
CANDIDATE_ISSUED
  |
  v
CANDIDATE_VALIDATED
  |
  +----fail----> CANDIDATE_REJECTED
  |
  v
READY_FOR_SWITCH
  |
  +--approval--> SWITCHING
                    |
                    v
                 SWITCHED
                    |
                    v
              LIVE_VALIDATION
                /       \
             fail         pass
              |            |
              v            v
           ROLLBACK      DRAINING_OLD
                            |
                            v
                        REVOKING_OLD
                            |
                            v
                     VERIFYING_REVOKED
                            |
                            v
                          CLOSED
```

## Invariantes

1. Sólo una credencial `ACTIVE` por binding lógico.
2. `STAGED` nunca sustituye a `ACTIVE` sin transición registrada.
3. Replays se resuelven por `(rotation_id, operation_id)`.
4. `CLOSED` requiere receipt.
5. Revocación no se infiere por “request returned 200”; se verifica cuando el proveedor lo permite.
6. Un estado incierto fuerza reconciliation.
7. PipelineK persiste estado de workflow; ASV persiste verdad de credencial.
