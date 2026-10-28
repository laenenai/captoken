# Quickstart

Mints a root delegation token, narrows it offline to an execution token, and
verifies one request.

```bash
go run ./examples/quickstart
```

Expected output:

```text
subject=alice permission=doc.read resources=1
```

## What to notice

- The root token is `TypeDelegation`; it authorises no operation. Only the
  derived `TypeExecution` leaf can be spent.
- `Derive` is offline. It uses the holder key returned beside the root token
  and never calls the issuer.
- The verifier gets only the root public key, the issuer identity, the schema
  and the revocation adapter.
- `Request.Now` is not set. `Verify` uses the verifier's clock.

## Production changes

- Replace `NewFixedClock` with the default system clock or your own
  `Clock`.
- Load the root key from an HSM/KMS rather than `GenerateKey`.
- Deliver `Minted.HolderKey` over a confidential channel, or use
  `MintSpec.HolderPublicKey` so the holder owns it.
- Supply a real `Revocations` adapter. The example uses `Memory` for
  readability.

Next: [`../holder-key`](../holder-key) for holder-owned keys, or
[`../revocation`](../revocation) for incident response.
