# Charter: `captoken`

**It does this one thing:** A bearer credential that can only ever be narrowed: minting, attenuation, typed caveats, offline verification, chain revocation, single-use nonces.

**It must not contain:** Any knowledge of principals, groups or policy. Subjects are opaque ids. It cannot answer "may they?" — only "is this credential valid, and what does it permit?"

## Why this file exists

A shared module with no stated boundary accretes until it is the dependency
every project has and nobody can reason about. This charter is the boundary.
Two mechanisms enforce it rather than merely stating it:

1. **`mise run api-diff`** compares the importable API against the last root
   tag with `apidiff`, and the release workflow validates the tagged tree with
   `gorelease`. Growing the public surface is visible in that report, so a new
   responsibility cannot slip in quietly. Internal packages are not part of the
   compatibility surface. Before 1.0 incompatible changes are reported and
   documented in `CHANGELOG.md`/`UPGRADING.md`; from 1.0 they fail the gate.
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
   reimplementing it. That service is deliberately **not** part of this
   module: captoken defines the ports (`reserve.Counters`,
   `reserve.Revocations`, `reserve.Nonces`) and fails closed, while the
   production transport, storage and deployment live in a separate
   module/repo. Splitting them keeps the static token library free of a
   stateful service's availability and database dependencies.

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

### Decided 2026-10-23: JWT, with the partition by token type

The envelope is a **JWT chain**: EdDSA over Ed25519, proof-of-possession via
`cnf.jwk`, chain linkage via `par_hash` (SHA-256 of the parent's JWS signing
input), aligned with `draft-niyikiza-oauth-attenuating-agent-tokens` so this is
interoperable if that work progresses. Biscuit is retired as an option.

**A single JWT cannot attenuate; a chain of them can.** Each link is signed by
a key its parent bound in `cnf.jwk`, so a holder derives a narrower token
offline without the issuer, and verification walks the chain checking
subsumption. Every link is a plain JWT that any library can parse and
signature-check — which is precisely what "works as a service for other
implementations" requires, since a third party needs a library they already
have and 32 bytes of public key.

#### The objection to JWT, which is real and empirical

`crit` is the mechanism that should make an extension a verifier does not
understand fail closed. RFC 7515 is unambiguous — *"If any of the listed
extension Header Parameters are not understood and supported by the recipient,
then the JWS is invalid"* — and it is a MUST.

**Real libraries do not honour it.** Open issues confirm that tokens carrying
unknown `crit` entries are *accepted* by **go-jose**, **PyJWT** and
**auth0/node-jsonwebtoken**: three of the most widely used implementations
across three ecosystems. `go-jose/v4` added `ErrUnsupportedCriticalHeader`, so
it is fixable, but it cannot be assumed of whoever verifies our tokens. `crit`
also applies to **header parameters only, never claims**, so using it means
putting caveats in a header — unusual, and still dependent on the library.

The failure mode is the worst available: a well-meaning third party, using a
standard library correctly as documented, **silently accepting** a token whose
caveats it never evaluated.

Biscuit does not have this problem. A Datalog check is a query that must return
a result, so an unsatisfied check cannot be skipped — there is nothing to skip.
That property is genuinely better, and it is the only thing Biscuit was winning
on by the end.

#### Why that does not decide it for Biscuit

Because the dependency on `crit` is avoidable, and once avoided the argument
disappears:

> **Partition by token type, not by a critical-header flag.** Design so that a
> naive-but-correct JWT verification is *sound, merely incomplete*: a verifier
> checking signature, `exp`, audience and scope is right about everything it
> checked. Then every stateful caveat lives behind a token type that is never
> presented to a third party at all, because the operation it authorises
> requires a server-side reservation the token cannot carry.

A third party cannot be tricked into accepting a stateful token, because it is
not the party performing the limited operation.

**Corrected during implementation: the partition needs three token types, not
two.** With only `delegation` and `execution`, the property above is
unsatisfiable, because an execution token is precisely what *is* presented to a
third party. So a stateful caveat has nowhere to live. The third type is
`redemption`, whose `aud` names the issuer's own reservation service: a third
party refuses it on `aud` alone — a claim RFC 7519 requires be checked, and the
one claim every mainstream library does check correctly — without needing to
know that stateful caveats exist at all. That `aud` check, not the token type's
name, is the mechanism the property rests on.

**Also corrected: `crit` is not available even as defence in depth.** The
conclusion below stands, but the consolation prize does not exist. go-jose's
`supportedCritical` is a package-level variable with no extension point, so a
token carrying any `crit` entry is unverifiable by the one library that honours
`crit` — ours included. Emitting it would make our tokens unreadable by exactly
the implementation a careful third party reaches for. `crit` is therefore not
emitted, and the structural property Biscuit offered is obtained by partitioning
the problem instead of by the token format.

#### And the costs Biscuit would have added

Weighed against a property we no longer need it for. The spike found, against
`biscuit-go` v2.2.2: hierarchical scopes flatten to a string so containment
becomes `.starts_with`, demonstrated matching scope `fs/a` against sibling
`fs/ab` — **a new authorization bug class the structured comparison cannot
produce**; Datalog checks are existential, so injecting both
`uses_remaining(0)` and `uses_remaining(5)` authorises — a fail-open an `int`
field cannot express; and `Authorize()` echoes failing check literals,
reproducing a leaked certificate thumbprint, not configurable, in direct
contradiction of this module's rule that a refusal explains nothing.

And the multi-language interop that would most have justified it is the part
that **could not be demonstrated**: `biscuit-go` implements schema v3 against
reference vectors reaching v6, 13 of 38 Rust-generated vectors fail to parse
including third-party blocks, and Go→Rust/Java was untestable for want of
toolchains. An interop story that does not work is worth less than a documented
format a third party can implement with a library they already have.

#### What this module therefore contains

- the **typed caveat vocabulary** and its semantics — the ~2,000 lines where
  the hard-won bugs live, kept;
- the **JWT chain envelope**: minting, offline derivation, subsumption
  verification, `par_hash` linkage, Ed25519;
- `alg` **pinned to EdDSA and never read from the token to select a key** — the
  discipline that closes the algorithm-confusion family;
- the **published wire format with test vectors**, held to the standard
  `seal`'s formats are held to, because a format a third party cannot
  independently implement is not a service interface;
- the **ports for the stateful subset**, with an in-memory adapter for tests
  and a fail-closed stub; the **verification service** itself is a separate
  module/repo, because it owns a database, a transport and an availability
  budget that a static token library should not inherit.

### Superseded: what this did not settle before 2026-10-23

Kept because the reasoning still applies if the decision is ever revisited.

It did not decide the envelope. Public-key verification and a documented
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

A consumer counts as having adopted this module when
`captokentest.RunCapabilitySuite` runs green with `Wiring.FullAdoption` in its
CI against its own wiring — its own schema and its own reservation,
revocation and nonce adapters. A run without FullAdoption is a legitimate
static-subset check, not full adoption. The test is deliberately behavioural.

One thing it does not establish, and which a consumer using the stateful
caveats owes on top of it: **two concurrent redemptions of a single-use
token must leave the counter at one and let only one operation through.**
The suite asserts everything that is a property of the caveats, and the one
property of a `Counters` adapter that needs no transaction — that concurrent
advances are not lost. Atomicity of the whole redemption is expressed
nowhere in the port, because a port that could express it would have to own
the transaction, and the point of the two-surface design is that the
consumer's transaction owns the operation too. So that assertion belongs in
the consumer's own tests, against its real store. `captokentest`'s package
doc says the same thing at more length.

| Consumer | State |
|---|---|
| cas | ADOPTED 2026-10-27: `internal/token` deleted, suite green against CAS's own schema, permissions and adapters |
| kgs | pending (phase 0) |
| acre | pending (no code yet; adopts from birth) |

## Provenance

Extracted per `kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md`
§6.1 (the six-module decomposition) and §6.2 (authority and projections).
