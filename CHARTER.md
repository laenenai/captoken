# Charter: `captoken`

**It does this one thing:** A bearer credential that can only ever be narrowed: minting, attenuation, typed caveats, offline verification, chain revocation, single-use nonces.

**It must not contain:** Any knowledge of principals, groups or policy. Subjects are opaque ids. It cannot answer "may they?" — only "is this credential valid, and what does it permit?"

## Why this file exists

A shared module with no stated boundary accretes until it is the dependency
every project has and nobody can reason about. This charter is the boundary.
Two mechanisms enforce it rather than merely stating it:

1. **`api.txt`** in this repo is the module's public API as a golden file,
   diffed in CI. Growing the public surface requires a reviewed diff, so a new
   responsibility cannot slip in quietly.
2. **The conformance suite** (`suite.go`, following the pattern of
   `cas/internal/blob/suite.go`) is the contract. A consumer counts as
   *adopted* when this module's suite runs green in that consumer's CI against
   its own wiring — not when someone says it is adopted.

A change that does not fit the charter belongs in a different module. A module
is created when a **second** consumer needs it, not in anticipation.

## It must work as a service for other implementations, and that settles most of the design

Owner's requirement, 2026-10-23. It is not a deployment note — it is the
constraint from which almost everything else follows, and it eliminated two
options I had been weighing.

The derivation, because each step forecloses something:

1. **A service for other implementations means verifiers exist that are not
   this module.** Not Go, not co-located, possibly not ours — a processor at
   the trust boundary, another organisation's service.
2. **So offline verification of the static caveats is a requirement**, not a
   property to price. Those verifiers cannot be made to call us for every
   access: that is an availability coupling where this service being down
   stops everyone's work, plus a trust and authentication relationship with
   each of them.
3. **So verification must be public-key.** An HMAC construction requires every
   verifier to hold the *signing* secret, which means any verifier can mint. It
   is not a weaker form of the property; it is the absence of it. This rules
   out adopting a macaroon library as-is, including `superfly/macaroon`, which
   is otherwise the best-proven Go option available.
4. **So the wire format is a published artifact**, documented and implementable
   by someone who is not us, with test vectors — the same standard `seal`'s
   formats are held to. A format that is merely whatever our encoder emits
   cannot be verified by a third party even in principle.
5. **And the stateful caveats need a service endpoint**, because they are not
   offline-verifiable at all: `MaxUses`, `ExpiresAfterFirstUse` and
   `MaxBytesTransferred` require a counter read inside the operation's own
   transaction. A third party must be able to get that check done without
   reimplementing it.

### Why that is safe rather than a split-brain

Because of the property the Biscuit spike proved and which this design adopts
whatever the envelope turns out to be: **a stateful caveat is a check over a
fact only the server can supply, so a verifier that cannot supply it refuses.**
Ignorance and refusal are the same outcome. A third-party verifier therefore
verifies the static subset offline, and *fails closed* on anything stateful
rather than skipping it — so the worst case of a partial verifier is a refused
request, never an accepted one.

That is what makes the two-surface design honest: the offline path cannot
silently grant more than it checked.

### What it does not settle

It does not decide the envelope. Public-key verification and a documented
format are available both by adopting Biscuit and by signing our own with
Ed25519, and the spike found real costs on the Biscuit side — a `.starts_with`
containment bug from flattening hierarchical scopes, an existential fail-open,
an error channel that echoes check literals, and a Go implementation at schema
v3 against reference vectors reaching v6 with 13 of 38 failing to parse. The
multi-language interop that would most justify adopting it is the part that
could not be demonstrated.

So the open question is narrower than it was: **sign our own envelope in a
published format, or adopt one whose cross-language verification we have not
been able to verify.** The requirement above does not favour the library as
much as it first appears, because an interop story that does not work is worth
less than a documented format a third party can implement.

## Adoption

| Consumer | State |
|---|---|
| cas | extraction pending (internal/token, ~3862 lines, built) |
| kgs | pending (phase 0) |
| acre | pending (no code yet; adopts from birth) |

## Provenance

Extracted per `kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md`
§6.1 (the six-module decomposition) and §6.2 (authority and projections).
