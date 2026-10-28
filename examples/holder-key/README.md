# Holder-supplied keys

Shows a delegation where the holder generates its own keypair and gives the
issuer only the public half. The issuer never handles the private key.

```bash
go run ./examples/holder-key
```

Expected output:

```text
subject=alice holder-private-key-never-sent=true
```

## What to notice

- `MintSpec.HolderPublicKey` binds the holder's public key in `cnf`.
- `Minted.HolderKey` is nil: there is no private key to deliver.
- The holder derives with `holderKey.Private`; any `crypto.Signer` works, so
  the private half can live in an HSM or KMS.
- The issuer still needs a root key. Keep that in an HSM/KMS too.

## Production changes

- Do not generate the holder key in the issuer's process. The holder should
  generate it locally and send only `Public`.
- Authenticate the holder before accepting its public key into a delegation.
- Rotate holder keys by issuing a new delegation; there is no key-update path
  inside an existing chain.
- Use a real revocation adapter, not `Memory`.

See [`../../docs/best-practices.md`](../../docs/best-practices.md) for key
custody and rotation.
