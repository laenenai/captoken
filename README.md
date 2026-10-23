# captoken

[![ci](https://github.com/laenenai/captoken/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/captoken/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/captoken.svg)](https://pkg.go.dev/github.com/laenenai/captoken)

A bearer credential that can only ever be narrowed.

Minting, attenuation, typed caveats, offline verification, chain revocation and
single-use nonces — for a credential that a holder can hand on in a weaker form
but never in a stronger one.

> **Status: design only.** This repository currently contains the charter and
> the boundary. There is no implementation yet, and no release. The
> implementation is an extraction of a working ~3,900-line package from a
> private consumer, scheduled after that consumer's current milestone.

## What it does

A token names a subject, a permission set narrowed to specific resources, an
expiry, a delegation chain with a depth limit, and a set of **typed caveats** —
each an independently tested predicate. Unknown caveat kinds fail closed,
because a verifier that ignores what it does not understand is a bypass.

Attenuation is one-directional by construction: a token can mint a child that
can do strictly less, and nothing can ever widen.

## What it does not do

It has no knowledge of principals, groups or policy. Subjects are opaque ids.
It cannot answer *"may they?"* — only *"is this credential valid, and what does
it permit?"* Authorization is a different module's job.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary, and the two mechanisms that enforce it
- [`SECURITY.md`](SECURITY.md) — reporting, and what the conformance suite does and does not prove
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
