# Examples

Runnable programs that show the patterns captoken is designed for. Every
example is a `main` package in this module:

```bash
go run ./examples/quickstart
go run ./examples/holder-key
go run ./examples/revocation
go run ./examples/stateful-redemption
```

They use fixed clocks and in-memory adapters so their output is stable across
runs; the generated keys still make the token bytes different each time. None
of those choices is a production recommendation by itself; each README calls
out what changes when the example leaves a laptop.

| Example | Use case | Demonstrates |
|---|---|---|
| [`quickstart`](quickstart) | A gateway issues a delegated capability and a holder narrows it | Mint a delegation, derive an execution token offline, verify a request |
| [`holder-key`](holder-key) | A holder keeps its private key in its own custody or HSM | `MintSpec.HolderPublicKey`, `crypto.Signer`, no private key in the token |
| [`revocation`](revocation) | Incident response must kill a whole delegation tree | Revoking `Verified.ChainID`; every descendant is refused |
| [`stateful-redemption`](stateful-redemption) | A one-shot operation must happen at most once | `TypeRedemption`, `MaxUses(1)`, `Reservations`, transaction ordering |

## Best practices these examples demonstrate

- **Use delegation for parents, execution for leaves.** A delegation token
  cannot spend authority; an execution token cannot be extended. This is what
  makes a truncated chain powerless.
- **Keep root keys in an HSM or KMS.** `MinterConfig.RootKey` is a
  `crypto.Signer`; the examples pass an `ed25519.PrivateKey` only to keep the
  code short.
- **Prefer holder-supplied keys for real delegations.** If the holder supplies
  `HolderPublicKey`, the issuer never sees the private half.
- **Let the verifier own time.** The examples set a `Clock`; production should
  use `SystemClock`. Do not try to control time through `Request.Now`.
- **Wire revocation.** `Revocations` is required. Use `NoRevocation: true` only
  for a deployment that has deliberately decided it does not revoke.
- **Never use `reserve.Memory` in production.** It is per-process and has no
  transaction. The production reservation service is a separate module/repo;
  the counters must be read, checked and advanced inside the operation's
  transaction.
- **Advance counters after success, not before.** A failed operation must not
  consume a use or a byte allowance.
- **Run the conformance suite.** `captokentest.RunCapabilitySuite` against your
  own schema, permissions and adapters is the adoption test.

See [`../docs/best-practices.md`](../docs/best-practices.md),
[`../docs/use-cases.md`](../docs/use-cases.md) and
[`../docs/quickstart.md`](../docs/quickstart.md) for the full guidance.
