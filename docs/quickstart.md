# Quickstart

This walkthrough mints a delegation token, narrows it offline to an execution
token, and verifies the result. The complete program is
[`examples/quickstart`](../examples/quickstart/main.go); run it with:

```bash
go run ./examples/quickstart
```

## 1. Declare the resource hierarchy

A `ResourceSchema` is the consumer's own tree. It is data, not code this module
interprets. The outermost level is always required; a level marked `Repeats`
may occur zero or more times below it.

```go
schema, err := captoken.NewResourceSchema(
    captoken.SegmentKind{Name: "tenant"},
    captoken.SegmentKind{Name: "fileset", Repeats: true},
    captoken.SegmentKind{Name: "document"},
)
if err != nil {
    return err
}
tenant, err := schema.Path(captoken.Segment{Kind: "tenant", ID: "acme"})
if err != nil {
    return err
}
document, err := schema.Path(
    captoken.Segment{Kind: "tenant", ID: "acme"},
    captoken.Segment{Kind: "fileset", ID: "contracts"},
    captoken.Segment{Kind: "document", ID: "d-1"},
)
if err != nil {
    return err
}
```

A path that was not built through this schema is the zero `ResourcePath`, and
every operation refuses it. Decode-side paths are revalidated against the same
schema, so a token signed under a different hierarchy is refused.

## 2. Mint the root delegation

The root key is the issuer's signing key. It never appears in a token. The
root link binds a holder key in `cnf`; the holder uses that key to derive
children.

```go
rootKey, err := captoken.GenerateKey(nil)
if err != nil {
    return err
}
clock := captoken.NewFixedClock(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
minter, err := captoken.NewMinter(captoken.MinterConfig{
    Issuer:  "issuer.example",
    RootKey: rootKey.Private,
    Schema:  schema,
    Clock:   clock,
})
if err != nil {
    return err
}
root, err := minter.Mint(captoken.MintSpec{
    Type:        captoken.TypeDelegation,
    Subject:     "alice",
    Audience:    []captoken.Audience{"api.example"},
    ExpiresAt:   clock.Now().Add(24 * time.Hour),
    Permissions: captoken.NewPermissionSet("doc.read", "doc.write"),
    Resources:   []captoken.ResourcePath{tenant},
})
if err != nil {
    return err
}
```

`Minted.Token` is the presentation string. `Minted.HolderKey` is the private
half of the bound holder key; deliver it to the holder over a confidential
channel, never inside the token.

### Holder-supplied keys

If the holder already owns a key, pass its public half instead:

```go
holder, _ := captoken.GenerateKey(nil)
root, _ := minter.Mint(captoken.MintSpec{
    // ...
    HolderPublicKey: holder.Public,
})
// root.HolderKey is nil: the issuer never saw the private half.
```

`MinterConfig.RootKey` and the `holderKey` argument to `Derive` accept any
`crypto.Signer` whose `Public()` is an Ed25519 key, so the private material can
stay in an HSM or KMS.

## 3. Derive a narrower execution token

Derivation is offline. It does not call the issuer and does not verify the
parent's signature, because the holder may not have the root public key. It
does refuse a child that would widen the parent.

```go
deriver, err := captoken.NewDeriver(captoken.DeriverConfig{
    Schema: schema,
    Clock:  clock,
})
if err != nil {
    return err
}
leaf, err := deriver.Derive(root.Token, root.HolderKey, captoken.MintSpec{
    Type:        captoken.TypeExecution,
    Subject:     "alice",
    Audience:    []captoken.Audience{"api.example"},
    ExpiresAt:   clock.Now().Add(time.Hour),
    Permissions: captoken.NewPermissionSet("doc.read"),
    Resources:   []captoken.ResourcePath{document},
})
if err != nil {
    return err
}
```

An execution token is terminal: it binds no holder key and cannot be a parent.
A delegation prefix is therefore powerless, which is why the format needs no
seal or proof.

## 4. Verify a request

The verifier owns the clock. `Request.Now` is ignored by `Verify`; use
`VerifyAt` when a test or replay needs a specific instant. A zero `Request.Now`
passed directly to `CheckAll` is refused rather than interpreted as year 1.

```go
memory := captoken.NewMemory()
verifier, err := captoken.NewVerifier(captoken.VerifierConfig{
    Issuer:      "issuer.example",
    RootKeys:    []ed25519.PublicKey{rootKey.Public},
    Audience:    "api.example",
    Schema:      schema,
    Clock:       clock,
    Revocations: memory,
})
if err != nil {
    return err
}
verified, err := verifier.Verify(context.Background(), leaf.Token, captoken.Request{
    Permission: "doc.read",
    Resource:   document,
})
if err != nil {
    return err
}
fmt.Println(verified.Subject, verified.Permissions, verified.TerminalResources)
```

`Revocations` is required. If the deployment deliberately does not revoke, set
`NoRevocation: true`; leaving both unset is a construction error, not a silent
skip. `Reservations` is optional, but a verifier without it refuses a
redemption token rather than skipping the counter check.

## 5. Revoke the chain

Revocation keys on the root token id, which every descendant carries as
`cid`. One record kills the whole tree.

```go
if err := memory.Revoke(context.Background(), verified.ChainID); err != nil {
    return err
}
_, err = verifier.Verify(context.Background(), leaf.Token, captoken.Request{
    Permission: "doc.read",
    Resource:   document,
})
if !errors.Is(err, captoken.ErrRevoked) {
    return fmt.Errorf("after revocation: %w", err)
}
```

See [`examples/revocation`](../examples/revocation/main.go) for a runnable
version and [`best-practices.md`](best-practices.md) for production guidance.
