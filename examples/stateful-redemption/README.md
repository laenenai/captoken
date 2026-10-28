# Single-use redemption

Shows a `TypeRedemption` token carrying `MaxUses(1)`, verified by a
reservation service that reads the counter and advances it only after the
guarded operation.

```bash
go run ./examples/stateful-redemption
```

Expected output:

```text
first-redemption=allowed second-redemption=refused
```

## What to notice

- Stateful caveats live only on a `TypeRedemption` token.
- The token's `aud` names the reservation service. A third-party gateway
  refuses it on `aud` alone and never needs to know the caveat vocabulary.
- `Verify` reads the counter; it never advances it.
- The caller advances the counter after the operation succeeds. The second
  verification is refused because `MaxUses(1)` is spent.
- The real transaction boundary is the caller's: read, verify, perform,
  advance, commit.

## Production changes

- Do not use `reserve.Memory` in a real deployment. It cannot provide
  cross-process atomicity or the caller's transaction.
- The production reservation service is a separate module/repo. Implement
  `Counters`, `Revocations` and, if needed, `Nonces` against its store.
- Use `Nonces.Consume` for at-most-once *operations* when a retryable request
  must not repeat the operation even though it is the same redemption.
- Alert on `ErrBackend`; never turn a backend failure into an allow.

See [`../../docs/best-practices.md`](../../docs/best-practices.md) and
[`../../docs/use-cases.md`](../../docs/use-cases.md).
