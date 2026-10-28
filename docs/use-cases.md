# Use cases

captoken is for **delegation of authority over a resource**, not for
authentication or policy. If a service needs to know *who* a caller is, use an
identity provider. If it needs to know *whether this holder may do this one
thing, on this one resource, until this instant, with an auditable chain of
narrowing*, captoken is the right shape.

## Delegated upload and download

A storage service issues a root delegation token over a tenant or fileset. A
client derives an execution token over one document and presents it to an
upload or download endpoint. The endpoint verifies the token and checks the
request's permission and resource against every link.

- Use `TypeDelegation` for the root so it cannot be spent directly.
- Use `TypeExecution` for the leaf so it cannot be extended.
- Use `AllowedContentTypes`, `MaxContentLength` and `ClientCIDR` on the leaf
  when the upload path needs them.
- Store holder private keys in the client's keychain or HSM, not in the
  token.

This is the pattern inherited from CAS; see the conformance suite's
`Minting` and `StatefulCaveats` cases for the edge conditions.

## Data-room and document workflows

A data room grants a reviewer read access to a folder, then derives a token
for a specific document and rendition. `Watermark` can require a rendition
label, and `RequireAuthenticatedRecipient` can insist the bearer is an
authenticated principal rather than an anonymous holder of the bytes.

- Put the folder scope on the delegation token and the document scope on the
  execution token.
- Use `ExpiresAt` and `NotBefore` for review windows.
- If the workflow needs at-most-once delivery, use a redemption token and the
  reservation service, not a long-lived execution token.

## AI training and dataset licensing

A dataset owner grants a model trainer permission to read a shard for a fixed
window. The trainer may sub-delegate to a preprocessing job with a narrower
resource and permission set, but cannot add a permission the owner never
granted.

- Use `PermissionSet` labels such as `dataset.train` and `dataset.evaluate`.
- Use `MaxBytesTransferred` or `MaxUses` if the licence is metered; those are
  stateful and need the reservation service.
- Use `RequireDeclaredDigest` when the downstream pipeline must declare the
  content address it is about to consume.
- Revocation by root chain id lets the owner stop an entire training run
  without tracking every derived token.

## Edge and offline verification

A CDN, gateway or customer premises appliance verifies execution tokens with
only the issuer's public key. It needs no call to the issuer and no shared
secret.

- Distribute the trusted root keys and the resource schema with the verifier.
- Use `VerifyAt` only for replaying a recorded decision; otherwise let the
  verifier's clock decide.
- If the edge cannot reach the revocation backend, it must fail closed or be
  configured with an explicit `NoRevocation` decision. Do not silently skip
  revocation.
- A stateful token is refused at the edge on `aud` alone; only the
  reservation service can redeem it.

## Single-use redemption

A one-shot operation — a destructive export, a payment release, a one-time
download — issues a `TypeRedemption` token whose `aud` is the reservation
service and carries `MaxUses(1)`. The service reads the counter inside the
operation's transaction, verifies, performs the operation, then advances the
counter only on success.

- The caller's transaction is the atomicity boundary; the port cannot provide
  it.
- If the operation is retryable but must happen at most once per *operation*,
  record a nonce through `Nonces.Consume` as well.
- A third-party gateway refuses the same token on `aud`, so the partition is
  enforced without a critical-header flag.

## Multi-tenant API capabilities

An API platform issues a root delegation over a tenant to a partner. The
partner derives per-customer execution tokens. The platform verifies at the
edge with the partner's issuer identity and its own resource schema.

- Keep one issuer identity per trust domain; the verifier accepts exactly one
  `Issuer`.
- Rotate root keys with a staged `RootKeys` list and thumbprint inventory.
- Use `DelegationDepth` to cap how far a partner can attenuate.
- Use `ProcessorAudience` when a downstream processor has its own identity.

## Patterns this module is not for

- **Replacing a session or an OIDC ID token.** It has no browser flow, no
  refresh token, no user claims and no revocation-by-user semantics.
- **Centralized policy evaluation.** It carries permissions, but it does not
  know roles, groups, relationships or obligations. Ask your policy engine
  after verification.
- **High-frequency, short-lived credentials without a revocation plan.** Every
  verifier needs a revocation answer; if the backend is unavailable, the safe
  outcome is a refusal.
- **Storing application state in claims.** The claim set is closed; adding a
  field is a wire-format change, not a configuration option.
