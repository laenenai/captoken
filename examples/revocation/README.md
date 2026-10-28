# Chain-wide revocation

Revokes a root chain identifier and shows that a derived execution token is
refused.

```bash
go run ./examples/revocation
```

Expected output:

```text
revoked=true descendants-refused=true
```

## What to notice

- `Verified.ChainID` is the root link's token id; every descendant carries it
  as `cid`.
- One `Revoke` call kills the root and every token derived from it.
- The second verification returns `captoken.ErrRevoked`. A revocation backend
  failure returns `captoken.ErrBackend` instead, without the driver detail.
- Revocation is idempotent and has no undo.

## Production changes

- Use a durable, replicated revocation store. A per-process `Memory` is only
  for tests.
- Make `Revoke` idempotent and monitor availability: verification fails
  closed if the backend is unavailable.
- Decide explicitly between a real backend and `NoRevocation: true`; leaving
  both unset is a construction error.
- Keep the revocation identifier in your audit log, but not the token or key.

See [`../../docs/best-practices.md`](../../docs/best-practices.md) for backend
failure and key-rotation guidance.
