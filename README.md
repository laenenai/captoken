# captoken

[![ci](https://github.com/laenenai/captoken/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/captoken/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/captoken.svg)](https://pkg.go.dev/github.com/laenenai/captoken)

A bearer credential that can only ever be narrowed.

Minting, attenuation, typed caveats, offline verification, chain revocation and
single-use nonces — for a credential that a holder can hand on in a weaker form
but never in a stronger one.

> **Status: pre-1.0.** The envelope, caveat vocabulary, wire format and
> conformance suite are implemented. Go 1.27.3 is the minimum supported
> version. Breaking changes are allowed before v1.0 but are recorded in
> [`CHANGELOG.md`](CHANGELOG.md) and [`UPGRADING.md`](UPGRADING.md) and checked
> by `mise run api-diff`.

## Quickstart

```bash
go get github.com/laenenai/captoken
go run ./examples/quickstart
go run ./examples/stateful-redemption
```

```go
schema, _ := captoken.NewResourceSchema(
    captoken.SegmentKind{Name: "tenant"},
    captoken.SegmentKind{Name: "document"},
)
tenant, _ := schema.Path(captoken.Segment{Kind: "tenant", ID: "acme"})
document, _ := schema.Path(
    captoken.Segment{Kind: "tenant", ID: "acme"},
    captoken.Segment{Kind: "document", ID: "d-1"},
)

rootKey, _ := captoken.GenerateKey(nil)
minter, _ := captoken.NewMinter(captoken.MinterConfig{
    Issuer:  "issuer.example",
    RootKey: rootKey.Private,
    Schema:  schema,
})
root, _ := minter.Mint(captoken.MintSpec{
    Type:        captoken.TypeDelegation,
    Subject:     "alice",
    Audience:    []captoken.Audience{"api.example"},
    ExpiresAt:   time.Now().Add(24 * time.Hour),
    Permissions: captoken.NewPermissionSet("doc.read", "doc.write"),
    Resources:   []captoken.ResourcePath{tenant},
})

deriver, _ := captoken.NewDeriver(captoken.DeriverConfig{Schema: schema})
leaf, _ := deriver.Derive(root.Token, root.HolderKey, captoken.MintSpec{
    Type:        captoken.TypeExecution,
    Subject:     "alice",
    Audience:    []captoken.Audience{"api.example"},
    ExpiresAt:   time.Now().Add(time.Hour),
    Permissions: captoken.NewPermissionSet("doc.read"),
    Resources:   []captoken.ResourcePath{document},
})

verifier, _ := captoken.NewVerifier(captoken.VerifierConfig{
    Issuer:      "issuer.example",
    RootKeys:    []ed25519.PublicKey{rootKey.Public},
    Audience:    "api.example",
    Schema:      schema,
    Revocations: captoken.NewMemory(),
})
verified, err := verifier.Verify(context.Background(), leaf.Token, captoken.Request{
    Permission: "doc.read",
    Resource:   document,
})
```

See [`docs/quickstart.md`](docs/quickstart.md) for the complete walkthrough,
including key custody, time and revocation.

## What it does

A token names a subject, a permission set narrowed to specific resources, an
expiry, a delegation chain with a depth limit, and a set of **typed caveats** —
each an independently tested predicate. Unknown caveat kinds fail closed,
because a verifier that ignores what it does not understand is a bypass.

Attenuation is one-directional by construction: a token can mint a child that
can do strictly less, and nothing can ever widen.

## The envelope

A **chain of JWTs**: EdDSA over Ed25519 and proof-of-possession via
`cnf.jwk`. Every non-root link commits to its parent by `par_hash`, while the
parent's bound key enforces which key could have signed it. Every link is an
ordinary compact JWS that any JOSE library can parse and signature-check, which
is what "works as a service for other implementations" requires — a third party
needs a library they already have and 32 bytes of public key.

A holder derives a narrower token **offline, with no call to the issuer**,
because the parent names the key its child must be signed by. No private key is
ever part of a token's serialized form, so a recipient of the bytes alone can
never derive from them. The issuer may generate a holder key, or bind a public
key the holder supplied (`MintSpec.HolderPublicKey`); either side may sign
through a `crypto.Signer` backed by an HSM or KMS.

Tokens are partitioned **by type**, not by a critical-header flag:

| type | may be a parent | authorises an operation | may carry a stateful caveat |
|---|---|---|---|
| `delegation` | yes | no | no |
| `execution` | no | yes | no |
| `redemption` | no | yes | yes |

Two results follow. A **truncated chain is powerless** with no seal and no
proof, because every proper prefix ends in a delegation token, which authorises
nothing. And a **stateful caveat can never reach a verifier that cannot
evaluate it**, because it lives only on a redemption token whose `aud` names
the reservation service — so a third party refuses it on `aud`, a claim every
mainstream JWT library checks correctly, rather than on `crit`, which three of
them do not.

## The central invariant

> No sequence of derivations can produce a token permitting more than its
> ancestor.

It is enforced twice. Verification refuses any link that does not narrow its
parent in every dimension this module orders. It also computes the effective
permission set as the intersection of every link's permission set, and the
earliest expiry across the chain, so a widening link that somehow got signed is
both rejected and powerless. Resources are validated against the consumer's
schema at every link and are reported as `Verified.TerminalResources`; use the
terminal field only after the chain has passed verification, not as a substitute
for checking the request against every link.

## What it does not do

It has no knowledge of principals, groups or policy. Subjects are opaque ids.
It cannot answer *"may they?"* — only *"is this credential valid, and what does
it permit?"* Authorization is a different module's job.

The stateful reservation service is deliberately **not** in this module. The
`reserve` package defines the ports and ships an in-memory adapter for tests;
the production service and its transport live in a separate module/repo. A
verifier without `Counters` fails closed on a redemption token. The verifier
also does not consume nonces: the operation owner records a nonce through its
`Nonces` adapter after a successful operation, in the same transaction.

## Layout

The root `captoken` package is a facade of type aliases and thin forwards. The
authoritative packages are public so godoc and pkg.go.dev show their fields and
methods:

- `domain` — value objects, resource schemas and clocks
- `caveat` — the closed caveat vocabulary, request facts and `CheckAll`
- `chain` — minting, derivation, verification and the JWS envelope
- `reserve` — the stateful ports and the test adapter
- `captokentest` — the behavioural conformance suite

## Development

`mise` is the single source of truth for tool versions and tasks:

```bash
mise install
mise run fmt
mise run test          # no containers
mise run test-all      # race detector
mise run check         # fmt, tidy, lint, build, tests, vuln, api-diff, vectors
mise run api-diff      # apidiff against the last root tag
mise run release-check # gorelease from a clean checkout
```

Contributor and compatibility rules are in [`CONVENTIONS.md`](CONVENTIONS.md).

## Documentation

- [`docs/quickstart.md`](docs/quickstart.md) — a complete minimal deployment
- [`docs/best-practices.md`](docs/best-practices.md) — key custody, time,
  revocation, storage and conformance
- [`docs/use-cases.md`](docs/use-cases.md) — patterns this module is designed
  for, and patterns it is not
- [`CHARTER.md`](CHARTER.md) — the boundary and the two mechanisms that enforce it
- [`docs/wire-format.md`](docs/wire-format.md) — the published format, and the
  contract a third-party verifier is held to. Pinned by
  `chain/testdata/vectors.json`, verified both directly and by a verifier
  written from the document alone
- `captokentest.RunCapabilitySuite` — the conformance suite. A consumer counts
  as fully adopted when it runs green with `FullAdoption: true` in its own CI,
  against its own schema and stateful adapters. A static-only run may omit
  `Counters`/`Nonces`; those subtests then skip explicitly.
- [`SECURITY.md`](SECURITY.md) — reporting, and what the conformance suite does
  and does not prove
- [`CHANGELOG.md`](CHANGELOG.md), [`UPGRADING.md`](UPGRADING.md) — release
  history and breaking changes
- [`examples/`](examples) — runnable quickstart, holder-key, revocation and
  stateful-redemption programs, each with a README and production notes
- `mise run api-diff` — the importable API diff against the last tag

## License

Apache-2.0. See [`LICENSE`](LICENSE).
