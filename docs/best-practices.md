# Best practices

This module makes a narrow promise: it decides whether a credential is valid
and whether it permits a particular request. Deploying it well means treating
keys, time, revocation and the stateful counters as production dependencies,
not as test fixtures.

## Keys and custody

- **Root private keys belong in an HSM, KMS or an equivalently restricted
  signer.** `MinterConfig.RootKey` accepts a `crypto.Signer`, so the key need
  not be a Go byte slice. The issuer should never need to export it.
- **Publish only the root public key to verifiers.** `Minter.RootPublicKey`
  returns it. Multiple root keys are accepted during rotation; there is no
  `kid` in the token, so a verifier tries every trusted key. Name keys in your
  own inventory with `captoken.PublicKeyThumbprint` and retire the old key only
  after every token it signed has expired.
- **Decide who generates holder keys.** If `MintSpec.HolderPublicKey` is
  omitted, `Mint` generates a keypair and returns the private half as
  `Minted.HolderKey`; that is convenient but means the issuer handles the
  private half and must deliver it securely. Supplying `HolderPublicKey`
  keeps the private half with the holder and is the better default for a real
  delegation.
- **Never put a private key in a token, a log, a metric label or an error.**
  The format has no private-key field; the API returns a generated holder key
  beside the token, never inside it.
- **Treat a zero or malformed key as a configuration bug.** Constructors reject
  identity and small-order Ed25519 public keys, because Go's verifier would
  otherwise accept a crafted signature under them.

## Time

- **The verifier owns "now".** `Verify` reads `VerifierConfig.Clock` and
  ignores `Request.Now`, so a presenter cannot extend a token's life. Set the
  clock explicitly in tests; use `VerifyAt` for a replay or a recorded
  decision, with a non-zero instant.
- **`CheckAll` is lower-level.** If you call it directly, populate
  `Request.Now`; a zero value is refused because it would make an expired grant
  look valid.
- **Keep clock skew small and symmetric.** The library applies a one-minute
  tolerance to time bounds. Do not compensate by extending token expiry; make
  the machines agree.

## Revocation

- **Wire a revocation backend in production.** `VerifierConfig.Revocations` is
  required. `NoRevocation: true` is an explicit deployment decision for a
  system that genuinely has no revocation requirement, not a default.
- **Make `Revoke` idempotent.** Revocation has no undo. Revoking an
  already-revoked chain must succeed; a retry must not fail the caller.
- **Revoke the chain, not each token.** `Verified.ChainID` is the root token
  id. One record invalidates every descendant.
- **Fail closed on backend failure.** A verifier returns `ErrBackend` without
  the driver message. Do not turn that into an allow; return a server error and
  alert. The same applies to `Reservations` failures.
- **Plan revocation availability.** If revocation is unavailable, verification
  fails closed. Size and monitor the backend accordingly.

## Stateful caveats and nonces

- **`MaxUses`, `ExpiresAfterFirstUse` and `MaxBytesTransferred` need a
  transactional counter.** Read the snapshot, verify, perform the operation,
  then advance the counter in the same transaction. Never advance before the
  operation succeeds.
- **Do not use `reserve.Memory` in production.** It is per-process and cannot
  provide the transaction or cross-process atomicity the ordering discipline
  requires.
- **Nonces are operation-scoped.** `Nonces.Consume` records that one operation
  happened; `MaxUses(1)` records that the chain was redeemed. A retry of the
  same operation must not consume twice, while a separate redemption may. The
  verifier does not consume a nonce; the operation owner does, in its own
  transaction.
- **The reservation service is a separate module/repo by design.** This module
  defines the ports (`reserve.Counters`, `reserve.Revocations`,
  `reserve.Nonces`) and fails closed. It does not ship a production transport.

## Resource schemas and permissions

- **Declare the schema once at the boundary and pass the same value to the
  minter, deriver and verifier.** A path from a different schema is refused at
  mint and at verify.
- **The outermost level is not optional,** even when it repeats. A path cannot
  begin halfway down the tree.
- **Keep permissions as opaque capability labels.** This module compares them
  for equality and set containment; it does not know your policy vocabulary.
  Grant the smallest set that the operation needs.
- **Use terminal resources only after verification.** `Verified.TerminalResources`
  is the leaf link's scope; the request has already been checked against every
  link's scope. If you need the full effective scope for a downstream
  operation, derive it from the chain's grants rather than assuming the leaf is
  the whole story.

## Tokens and request handling

- **Choose the weakest token type that works.** Delegation tokens authorise no
  operation. Execution tokens cannot be parents. Redemption tokens carry the
  stateful caveats and must name the reservation service in `aud`.
- **Validate at mint as well as at verify.** `Mint` runs the same canonical
  decode a verifier does, so an empty subject, a malformed permission, a
  negative caveat value or a cross-schema resource fails at the issuer rather
  than at the holder.
- **Do not expose `ErrInvalidToken` details to clients.** The verifier
  deliberately returns the same sentinel for every structural failure. Log
  only on your side, and never log token material.
- **Distinguish the three outcomes.** `ErrInvalidToken` means the credential is
  not valid; `ErrCaveatNotSatisfied` means it is valid but does not permit this
  request; `ErrBackend` means the stateful backend failed. They lead to
  different HTTP statuses and different alerts.
- **Enforce a request-size limit at your edge too.** The library caps a
  presentation at 64 KiB and every signed list at 256 entries, but rejecting
  oversized requests before parsing is still cheaper.

## Adoption and release

- **Run `captokentest.RunCapabilitySuite` in the consumer's CI** against the
  consumer's own schema, permissions and adapters. Set
  `Wiring.FullAdoption: true` for the full adoption claim: it requires
  `Counters`, `Nonces` and `Revocations` and proves the stateful/nonce paths
  run rather than skip. Supply a real `Revocations` implementation; it is
  always required.
- **Run `mise run check` before every merge.** It covers formatting, lint,
  build, race tests, `go vet`/vuln, the API diff and vector reproducibility.
- **Treat wire-format changes as a new format version.** Update
  `docs/wire-format.md`, the vectors and the changelog together. Do not update
  a pinned constant test to make a build green.
- **Follow the release policy.** Releases require two-person review and a
  signed tag; security reports go through the process in [`SECURITY.md`](../SECURITY.md).
  An external audit is required before v1.0.
