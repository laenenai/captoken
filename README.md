# captoken

[![ci](https://github.com/laenenai/captoken/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/captoken/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/captoken.svg)](https://pkg.go.dev/github.com/laenenai/captoken)

A bearer credential that can only ever be narrowed.

Minting, attenuation, typed caveats, offline verification, chain revocation and
single-use nonces — for a credential that a holder can hand on in a weaker form
but never in a stronger one.

> **Status: first increment, pre-release.** The caveat vocabulary, the JWT
> chain envelope and the published wire format are implemented and tested.
> Not yet built: the transport for the remote verification service the
> stateful caveats need — its ports are defined and its transport is
> stubbed, so a verifier without one refuses a stateful token rather than
> skipping the check.

## What it does

A token names a subject, a permission set narrowed to specific resources, an
expiry, a delegation chain with a depth limit, and a set of **typed caveats** —
each an independently tested predicate. Unknown caveat kinds fail closed,
because a verifier that ignores what it does not understand is a bypass.

Attenuation is one-directional by construction: a token can mint a child that
can do strictly less, and nothing can ever widen.

## The envelope

A **chain of JWTs**: EdDSA over Ed25519, proof-of-possession via `cnf.jwk`, and
each link bound to exactly one parent by `par_hash`. Every link is an ordinary
compact JWS that any JOSE library can parse and signature-check, which is what
"works as a service for other implementations" requires — a third party needs a
library they already have and 32 bytes of public key.

A holder derives a narrower token **offline, with no call to the issuer**,
because the parent names the key its child must be signed by. No private key is
ever part of a token's serialized form, so a recipient of the bytes alone can
never derive from them.

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
the issuer's own reservation service — so a third party refuses it on `aud`, a
claim every mainstream JWT library checks correctly, rather than on `crit`,
which three of them do not.

## The central invariant

> No sequence of derivations can produce a token permitting more than its
> ancestor.

It is enforced twice. Verification refuses any link that does not narrow its
parent in every dimension this module orders, and it computes the chain's
authority as the intersection of every link — so a widening link that somehow
got signed is both rejected and powerless. An adversarial suite attacks every
dimension at every link, and a mutation test removes each of the twelve
verification guards in turn and requires its witness attack to succeed, so the
suite's green is a statement about the guards rather than about the verifier
refusing things in general.

## What it does not do

It has no knowledge of principals, groups or policy. Subjects are opaque ids.
It cannot answer *"may they?"* — only *"is this credential valid, and what does
it permit?"* Authorization is a different module's job.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, and the two mechanisms that enforce it
- [`docs/wire-format.md`](docs/wire-format.md) — the published format, and the
  contract a third-party verifier is held to. Pinned by
  `internal/chain/testdata/vectors.json`, which is verified both directly and
  by a verifier written from the document alone
- `captokentest.RunCapabilitySuite` — the conformance suite. A consumer counts
  as having adopted this module when it runs green in that consumer's CI
  against its own wiring
- [`SECURITY.md`](SECURITY.md) — reporting, and what the conformance suite does and does not prove
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
