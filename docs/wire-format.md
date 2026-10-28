# captoken chain format, version 1

This document is a committed artifact. `chain/testdata/vectors.json`
pins it with worked examples; `TestVectors_VerifyCommittedTokens` verifies
those committed presentation strings directly, and
`TestVectors_AnIndependentImplementationAgrees` verifies them again with a
verifier written from **this document alone**, using nothing but
`crypto/ed25519`, `crypto/sha256` and `encoding/json`. A change to anything
described here must change this file, `FormatVersion`, and the vectors —
deliberately and together, never silently.

The charter's reason for all of that, in one sentence: *a format a third
party cannot independently implement is not a service interface.*

## What a captoken is

A **chain of JWTs**. Each link is an ordinary compact JWS that any JOSE
library can parse and signature-check. The root link is signed by the
issuer's root key; every other link is signed by a key its parent named, so
a holder can derive a narrower token **offline, with no call to the
issuer**, and a verifier that has already checked link *i* can check link
*i+1* with a key it found in link *i*.

Verification establishes one invariant above all others:

> **No sequence of derivations can produce a token permitting more than its
> ancestor.**

## Presentation

```
ct1~<link0>~<link1>~…~<linkN>
```

- `ct1` is the presentation syntax's version, and guards against a string
  from an unrelated system being fed in by mistake. It is separate from the
  claim-level `ctv`: a change to how links are joined need not change what a
  link says.
- `~` is the separator. It is unreserved in RFC 3986, so a presentation is
  safe in a URL, a header and a form field with no escaping. SD-JWT uses it
  for the same job.
- **Links are ordered root first.** `link0` is the root; `linkN` is the
  terminal link, the one that authorises something.
- Each link is a compact JWS with exactly three dot-separated segments. A
  JSON serialization, a detached payload and an unprotected header are all
  refused rather than interpreted.
- A verifier MUST bound the number of links. This implementation defaults to
  8 and caps configuration at 64, so that a hostile presentation cannot
  demand an unbounded number of signature checks before any has succeeded.
- A verifier MUST reject a presentation longer than **64 KiB**. The bound is
  applied before splitting or decoding; it keeps a hostile presenter's work
  proportional to a small, fixed input.

## Protected header

Exactly two members, and **nothing else is tolerated**:

```json
{"alg":"EdDSA","typ":"captoken+jwt"}
```

Member names appear in lexicographic order, which is what a JSON encoder
serializing a map produces; `TestHeaderIsExactlyAlgAndTyp` pins the bytes.

- `alg` MUST be `EdDSA` (Ed25519, RFC 8037). A verifier MUST compare it
  against that constant and MUST NOT use it to select a key or a
  verification routine. That is the discipline that closes the
  algorithm-confusion family: there is no table to dispatch through.
- `typ` MUST be `captoken+jwt`, per RFC 8725's recommendation that a JWT
  declare its application type, so one application's token cannot be
  replayed into another's.
- There is **no `kid`**, and `jwk`, `jku`, `x5u`, `x5c` and `crit` are all
  refused. A verifier that reads the token to decide which key to check the
  token with is where key confusion begins, so the token carries nothing
  that participates in key selection. Trusted root keys come from
  configuration, and a verifier tries each in turn.

### On `crit`, and why this format does not use it

`crit` is the JOSE mechanism that should make an extension a verifier does
not understand fail closed. RFC 7515 is unambiguous and it is a MUST. **Real
libraries do not honour it**: go-jose (before v4), PyJWT and
auth0/node-jsonwebtoken all accept unknown `crit` entries, which is the
objection the charter records.

This format does not emit `crit` at all, and the reason is stronger than
"we cannot rely on it". It was measured: `go-jose/v4` is the library that
implements `crit` **correctly**, returning `ErrUnsupportedCriticalHeader`
for an entry it does not recognize — and it offers no way to declare an
extension as supported, because its `supportedCritical` set is a
package-level variable. So a token carrying `crit:["anything"]` is
unverifiable by the single best-behaved implementation available, **our own
included**. Emitting `crit` would have made these tokens unreadable by
precisely the library a careful third party would reach for.

The guarantee `crit` was supposed to provide is obtained structurally
instead, by the token-type partition below.

## Claim set

Member order is part of the format, because the claim set is signed bytes.
Members appear in exactly this order; optional members are omitted
entirely rather than being present and null.

| claim | type | required | meaning |
|---|---|---|---|
| `ctv` | integer | yes | format version. **1.** A verifier MUST refuse a version it does not implement. |
| `ctt` | string | yes | token type: `delegation`, `execution` or `redemption`. See below. |
| `iss` | string | yes | opaque issuer identifier. Every link in a chain MUST carry the same one, and a verifier MUST check it against its configured issuer. |
| `sub` | string | yes | opaque subject identifier: who the link was minted for. |
| `aud` | array of string | on a terminal link | who may accept the token. Sorted, no duplicates. |
| `jti` | string | yes | unique identifier for this link. |
| `cid` | string | yes | the chain's identifier: **the root link's `jti`**, carried verbatim by every descendant. |
| `iat` | NumericDate | yes | when the link was issued, whole seconds. |
| `nbf` | NumericDate | no | not valid before, whole seconds. |
| `exp` | NumericDate | yes | not valid after, whole seconds. **Required** — a capability with no expiry is a liability, and requiring it means the subsumption rule never has to reason about a missing bound. |
| `prm` | array of string | yes | the opaque permission labels this link grants. Sorted, no duplicates, non-empty. |
| `res` | array of path | yes | the resource scopes this link covers. Non-empty. See *Resource paths*. |
| `cav` | array of caveat | no | the conditions beyond the four above. Sorted by kind, no duplicate kinds. See *Caveats*. |
| `cnf` | object | on a delegation link | `{"jwk": …}`, the key this link's children must be signed by. RFC 7800. |
| `par_hash` | string | on every non-root link | SHA-256 of the parent link's JWS signing input, base64url without padding. |

Identifiers (`iss`, `sub`, `jti`, `cid`, each `aud` entry), permission
labels, resource-level names and resource-segment IDs are non-empty, valid
UTF-8, at most **255 bytes**. Every list in the claim set is bounded at **256
entries**; a path is bounded at 256 segments.

A verifier MUST refuse:

- **a member it does not recognize.** A build that meets an unknown member
  does not implement the token's format, and evaluating the part it
  recognized is exactly the silent-acceptance failure this design exists to
  rule out. `ctv` is the mechanism for extension.
- **a member named twice.** `encoding/json` keeps the last duplicate and
  other implementations keep the first, so `{"ctt":"execution","ctt":"delegation"}`
  would mean two different things to two correct-looking verifiers. RFC 8725
  says the same and no mainstream library enforces it.
- **a list that is not canonical** — unsorted or containing duplicates —
  because a token that re-encodes differently from how it arrived is two
  byte sequences for one credential, and anything keyed on the bytes then
  has two keys for one token.
- **members out of canonical order.** The claim order is part of the signed
  format, not a presentation preference. A reordered object is refused rather
  than re-canonicalized.
- **invalid UTF-8 in the raw JSON bytes.** `encoding/json` would otherwise
  replace it with U+FFFD before the identifier check sees it, which is a
  silent reinterpretation of a signed value.
- **a required member that is absent or zero.** In particular `iat` MUST be a
  positive NumericDate and `exp` MUST be non-zero.
- **an optional member present as `null`.** An optional member is either
  omitted or carries its value; `null` is not a third spelling.
- **non-canonical JSON.** The header, claim set and JWK MUST be exactly the
  compact bytes a conforming encoder produces: no whitespace, no redundant
  escapes and no alternative spelling. The decoder re-encodes the parsed value
  and requires byte equality. HTML-sensitive characters (`<`, `>`, `&`) stay
  literal; Go's encoder still escapes U+2028 and U+2029, and conforming
  producers MUST match that.
- **non-canonical base64url.** The header, payload and JWK `x` value MUST use
  unpadded base64url with zero trailing pad bits.

### NumericDate

`exp`, `nbf` and `iat` are counts of whole seconds since the Unix epoch, per
RFC 7519. Sub-second precision is therefore lost when a bound is signed, and
**the direction it is lost in is a security property**: an issuer MUST floor
`exp` and ceil `nbf`, so that each bound moves inwards and a round trip
through the wire can only ever narrow what a token permits.

A verifier SHOULD apply a clock-skew tolerance of **60 seconds**,
symmetrically, to both bounds and to every time-based caveat. The tolerance
has to live in one place or a consumer building its own check gets none.

## Token types

The partition is the design, not a convenience. What a token is *for* decides
what it may carry.

| `ctt` | may be a parent | authorises an operation | may carry a stateful caveat | `cnf` | `aud` |
|---|---|---|---|---|---|
| `delegation` | yes | **no** | no | required | optional |
| `execution` | no | yes | no | forbidden | required |
| `redemption` | no | yes | **yes** | forbidden | required |

A verifier MUST check that:

- every **interior** link is a `delegation` token;
- the **terminal** link is `execution` or `redemption`;
- a `delegation` link carries `cnf` and a terminal link does not;
- a terminal link carries a non-empty `aud`.

### Why truncation is powerless, with no seal and no proof

A bearer holds every byte of every link, so nothing stops them presenting a
*prefix* of the chain. Two facts make that useless:

1. **Every proper prefix ends in a `delegation` link**, and a delegation
   token authorises no operation at all. It is a licence to derive, not a
   credential to spend.
2. **Deriving a new terminal link from an ancestor requires the key that
   ancestor named in `cnf`**, and no private key is ever part of a token's
   serialized form. A downstream holder never received it. Only the party the
   ancestor was handed to can derive from the ancestor, which is their own
   authority rather than an escalation.

The predecessor design (`cas/internal/token`) needed a dedicated `Proof`
field and sixty lines of argument for this. Here it falls out of the type
partition.

### Why a stateful caveat can only ever be on a `redemption` token

Three caveats — `max_uses`, `expires_after_first_use`,
`max_bytes_transferred` — are not offline-verifiable at all. Each reads a
counter that must be read inside the operation's own transaction and advanced
only once the operation has succeeded. That is a database's job, not a
token's.

So they live on a token type whose `aud` names **the issuer's own reservation
service**. A third-party verifier refuses such a token on `aud` — a claim RFC
7519 requires be checked, and which every mainstream library does check
correctly, unlike `crit`. It never has to know that stateful caveats exist,
and it cannot be tricked into accepting one it could not evaluate.

A verifier that *is* the reservation service reads the counters through its
own port, and refuses if it has none: ignorance and refusal are the same
outcome.

## The contract a third-party verifier is held to

This is the section to implement.

**The four checks.** A verifier MUST perform all of:

1. **Signature**, under the correct key for each link (see *Chain walk*),
   with `alg` compared against `EdDSA` and never read to select anything.
2. **`exp` and `nbf`**, on every link, with the skew tolerance above.
3. **`aud`**: the terminal link's `aud` MUST contain the verifier's own
   identifier.
4. **Scope**: the terminal link's `prm` MUST contain the permission being
   exercised, and one of its `res` entries MUST contain the resource being
   acted on.

**And the chain walk.** A verifier MUST also perform the chain walk,
`par_hash` linkage, the type rules and subsumption described below; those are
what make check 4 meaningful, since without them a link could claim any scope
it liked.

### The soundness property, stated precisely

> **A naive-but-correct JWT verification is sound, merely incomplete.** A
> verifier that checked signature, `exp`, `aud` and scope is *right about
> everything it checked.*

What makes that true, rather than merely likely:

- **Nothing a verifier is structurally unable to evaluate can reach it.**
  The only conditions that need data a verifier may not have are the three
  stateful caveats, and those appear only on a `redemption` token, which
  `aud` keeps away from anyone but the reservation service.
- **Every link restates the full condition set.** A derivation MUST restate
  every caveat kind its parent carries, at a value at least as restrictive,
  so the terminal link's claims are the chain's effective claims. Dropping a
  parent's caveat is a widening *by removal* and is refused.
- **Verification is an intersection, not a reading of the leaf.** A verifier
  SHOULD compute the effective permission set as the intersection of every
  link's `prm`, and the earliest `exp`. This implementation does. Resources
  are containment-checked at every link; the terminal link's scopes are
  reported separately as `Verified.TerminalResources`, not as a claim that
  the terminal scope is the whole chain's authority.

**The completeness obligation, which is contractual rather than structural.**
The caveat vocabulary is CLOSED: a verifier MUST refuse a `cav` entry whose
kind it does not recognize, exactly as it must refuse an unknown claim. An
issuer MUST NOT name in `aud` a verifier that does not implement the
vocabulary. `aud` is the enforcement point for that, and it is the one claim
every library checks.

## Rollout and versioning

The vocabulary is closed, but a closed vocabulary still has to grow safely.
The rule is **verifier first**:

1. Implement the new kind (or the new check) in every verifier that will
   accept tokens from the issuer, and release it.
2. Only then let an issuer put that kind on the wire. An issuer must not name
   in `aud` a verifier that has not deployed the checker; a verifier that
   meets an unknown kind refuses the token by design.
3. A structural change to the claim set, header or linkage is a new
   `FormatVersion` and a new `ctv`, with a new document and vectors. Adding a
   value to the existing caveat vocabulary is a compatible rollout under the
   same `ctv` only when step 1 has happened everywhere.

This is why `ctv` is a version of the format rather than a capability
negotiation: negotiation would let a presenter choose the verifier's
behaviour, and the format deliberately gives the presenter no such choice.

## Chain walk

For each link *i*, in order from 0:

1. Split the compact JWS into `header.payload.signature`. The **signing
   input** is `header + "." + payload` — the bytes as presented, not a
   re-encoding.
2. Validate the header (exactly `alg` and `typ`, exactly those values).
3. Decode the payload, refusing unknown members, duplicate members and a
   `ctv` the verifier does not implement.
4. Determine the verification key:
   - *i = 0*: one of the verifier's configured trusted root keys. Try each in
     turn. The token carries nothing that selects one.
   - *i > 0*: the Ed25519 public key in link *i-1*'s `cnf.jwk`. If link *i-1*
     has no `cnf`, refuse.
5. Verify the signature over the signing input.
6. Check `par_hash`:
   - *i = 0*: `par_hash` MUST be absent.
   - *i > 0*: `par_hash` MUST equal `base64url(SHA-256(signing input of link
     i-1))`, unpadded.
7. Check `iss` equals the configured issuer, and `cid` equals link 0's `jti`.
   Link 0's `cid` MUST equal its own `jti`.
8. Check the type rules.
9. For *i > 0*, check subsumption against link *i-1*.

### What `par_hash` secures, honestly

The `cnf` key chain already defeats re-ordering, splicing a link from
another chain, replaying a link within a chain, and removing a link —
because each link must be signed by the key its parent named, and those
keys are fresh per derivation.

`par_hash` secures the chain's **provenance**: that a link descends from the
parent it says it does. The case it uniquely catches is **key reuse** — if
one holder mints two sibling delegation tokens and binds the same child key
in both, a descendant of the narrow one verifies cryptographically under the
wide one too, and only `par_hash`, which that descendant itself committed to,
says which parent it was issued under.

It is **not** an independent bound on authority, and this document would be
wrong to claim it is: because every link restates its parent's caveats and
verification intersects every link, the terminal link already dominates, so
swapping an ancestor for a wider sibling cannot add authority. `par_hash` is
the backstop for the restatement rule and the integrity of the delegation
record. (A mutation test in `chain/mutation_test.go` is what
established this; the first version of that test claimed otherwise and was
wrong.)

## Subsumption

For every link *i > 0*, against its parent:

| dimension | rule |
|---|---|
| `prm` | child's set ⊆ parent's set |
| `res` | every child scope contained by at least one parent scope (see *Resource paths*) |
| `exp` | child's ≤ parent's |
| `nbf` | if the parent has one, the child MUST have one and it MUST be ≥ the parent's |
| `aud` | if the parent has one, the child's MUST be a non-empty subset of it |
| `cav` | for every kind the parent carries, the child MUST carry that kind at a value at least as restrictive; the child MAY add kinds the parent lacks |

`sub` is deliberately **not** ordered. A subject is an opaque identifier and
nothing here can rank two of them — delegating to another holder is what a
delegation token is for. A chain preserves every link's `sub`, so a consumer
that wants to police them can.

A delegation token's `aud` is the set its descendants may draw from. An
issuer that intends a chain to be able to produce a `redemption` token must
include the reservation service's identifier in it.

## Resource paths

A resource is a **sequence of segments**, outermost first. Each segment is a
two-element array of `[kind, id]`:

```json
"res": [ [["tenant","t1"],["fileset","a"],["document","d1"]] ]
```

A `kind` is a level name the consumer declared; an `id` is an opaque,
non-empty, valid-UTF-8 identifier. This module never interprets an `id`.

**Containment.** `outer` contains `inner` exactly when `outer`'s segments are
an **element-wise prefix** of `inner`'s, comparing each `(kind, id)` pair for
exact equality. Containment is reflexive.

**Why not one joined string.** Because containment would then be a string
prefix test, and the Biscuit spike demonstrated a prefix test matching the
scope `fs/a` against its **sibling** `fs/ab` — a new authorization bug class
that the structured comparison cannot express. Keeping the path structured
also means there is no separator to canonicalize, terminate or escape, so
there is no security-critical encoding to get right.

**The schema.** A consumer declares its hierarchy as an ordered list of
levels, each with a name and whether it may nest within itself. CAS's is:

```
tenant, fileset (repeats), document, slot, element
```

A path is well formed when its segment kinds walk that list left to right,
consuming one segment per level (or zero or more for a repeating level), with
no level skipped while a deeper one is present, and the path fully consumed.
A path MUST be non-empty and MUST begin at the first declared level.

An encoder MUST refuse a path its schema does not accept, which is what makes
a decoder's "well formed by construction" premise true. Two paths for the
same resource that differ in which optional levels they name do not contain
each other, so a consumer MUST always emit the complete ancestry.

The `res` array is sorted and deduplicated, by segment, then by kind then id
within a segment, then by length. Its entries are a **union**: a request is
in scope if at least one entry contains it.

## Caveats

```json
"cav": [ {"k":"max_content_length","v":1024}, {"k":"max_uses","v":3} ]
```

Entries are sorted by `k`, with no duplicate kinds. Two caveats of one kind
on a single link would have to be intersected to mean anything; the issuer
intersects first, or uses separate links. Caveats on different links
intersect naturally, because every one of them must pass.

The vocabulary is closed. An unrecognized `k` MUST be refused.

| `k` | `v` | stateful | meaning |
|---|---|---|---|
| `allowed_content_types` | array of string, sorted, unique | | the request's **sniffed** content type, matched verbatim, must be one of these |
| `client_cidr` | string, a masked CIDR prefix | | the client address must be inside the prefix |
| `delegation_depth` | integer ≥ 0 | | the **total** number of links presented, root included, must be ≤ this |
| `expires_after_first_use` | integer, seconds ≥ 0 | **yes** | refuses once this long after the chain's first redemption |
| `expires_at` | NumericDate | | carried as the `exp` claim, never as a `cav` entry |
| `max_bytes_transferred` | integer ≥ 0 | **yes** | bytes already served plus this request's length must not exceed this |
| `max_content_length` | integer ≥ 0 | | the request body's length must not exceed this |
| `max_uses` | integer ≥ 0 | **yes** | refuses once the chain has been redeemed this many times |
| `not_before` | NumericDate | | carried as the `nbf` claim, never as a `cav` entry |
| `permission_set` | array of string | | carried as the `prm` claim, never as a `cav` entry |
| `processor_audience` | string, non-empty | | the calling processor's opaque identity must match exactly |
| `require_authenticated_recipient` | `true` | | the bearer must be an authenticated principal, not an anonymous holder |
| `require_declared_digest` | `true` | | the upload must have declared a content address |
| `required_readiness` | array of string, sorted, unique | | the target's readiness state must be one of these |
| `resource_scope` | array of path | | carried as the `res` claim, never as a `cav` entry |
| `watermark` | string, non-empty | | the requested rendition label must match exactly |

Four kinds — `expires_at`, `not_before`, `permission_set`, `resource_scope` —
have a standard-claim counterpart and are carried **only** as `exp`, `nbf`,
`prm` and `res`. They are never `cav` entries, and a verifier MUST refuse one
that appears there. That placement is the partition's point: the four
dimensions that matter most are in claims a stock JWT library already checks,
not in a field such a library would skip.

### Fail-closed rules a verifier MUST implement

- An unknown length (`Content-Length` absent, a chunked request) fails every
  length-bounding caveat. A caveat that cannot verify a bound does not grant
  it by default.
- `allowed_content_types` matches the **sniffed** type of the bytes on the
  wire, never a caller-declared header, and compares the whole string
  verbatim. The sniffer never produces parameters, so
  `application/pdf; charset=../../x` fails the exact-match check with no
  special-case logic.
- A total chain length below 1 fails every `delegation_depth` caveat: 1 is
  the minimum (a never-derived token still has a root link), so 0 is
  unambiguously "nobody populated this".
- An unset client address fails every `client_cidr` caveat explicitly, not
  incidentally.
- An empty readiness label satisfies no `required_readiness`.
- A chain of zero links authorises nothing. Checking every link of an empty
  chain trivially succeeds, which would grant everything.
- An **empty** `prm` or `res` is never "unrestricted": it is a link that
  grants nothing.

### Negative values

There are none. Every integer caveat value is ≥ 0, and `9223372036854775807`
is refused, so arithmetic in a verifier has headroom. The Biscuit spike found
every negative sentinel in the predecessor's vocabulary to be a hazard; the
cleanest answer is that the wire form has none.

## Errors

A refusal names **nothing**: not the check that failed, not the link, not a
claim, not a value. A verifier that explains why a request was refused hands
an attacker a dimension to search along, and the search is cheap — flip one
field, read the message, repeat. Two outcomes are distinguished, because a
caller needs them, and neither carries detail:

- **invalid token** — the credential is not well formed, not correctly
  signed, not correctly linked, or widens an ancestor;
- **caveat not satisfied** — the credential is valid and does not permit this
  request.

An implementation MAY record the reason in its own logs. It MUST NOT return
it.

## Revocation and single use

- **The chain's revocation identifier is `cid`**, which is the root link's
  `jti` and is byte-identical in every descendant. Revoke it and every token
  ever derived from that root dies, with no enumeration of descendants and no
  walk of a revocation tree. (The predecessor hashed the whole token, so
  revoking a parent left its children alive.)
- It is immune to the canonicalization hazard a presented-bytes identifier
  has: `cid` is a claim inside the signed bytes, so there is nothing to
  re-encode and no canonical form to agree on.
- **A single-use nonce** is a separate record from the use counter. `max_uses`
  counts redemptions of a chain; a nonce records that one particular
  *operation* has been performed, which a retried request must not perform
  twice even though it is the same redemption.

The ports for both, and the ordering discipline the counters require, are in
`reserve`. The production reservation service and its transport are a separate
module/repo, **not part of this version of the format**; this module ships an
in-memory test adapter and a fail-closed stub.

## Library choice

This implementation signs and verifies each link through
**`github.com/go-jose/go-jose/v4` v4.1.6**, rather than hand-rolling JWS.

The reason is the charter's own: the module's central claim to a third party
is that *every link is a plain JWT any library can parse*. Our own code going
through a standard JOSE library rather than a bespoke encoder is what keeps
that claim honest — a hand-rolled encoder can drift from the specification in
ways only an outside implementer would discover. What this module keeps for
itself is everything JOSE does not specify: the claim set's canonical member
order, the strictness JOSE libraries do not provide (duplicate members,
unknown members, a header restricted to two parameters), the chain walk, and
subsumption.

Measured at the time of the library evaluation (Go 1.25.6); re-check with the pinned toolchain before changing the decision:

| | go-jose/v4 v4.1.6 | golang-jwt/jwt/v5 v5.3.1 |
|---|---|---|
| licence | Apache-2.0 | MIT |
| transitive dependencies | **none** | none |
| cgo | pure Go | pure Go |
| `govulncheck` | clean | clean |
| `alg` allowlist at parse | `ParseSigned(…, []SignatureAlgorithm{EdDSA})` | `WithValidMethods` |
| rejects `alg: none` | yes | yes |
| honours `crit` per RFC 7515 | **yes** (`ErrUnsupportedCriticalHeader`) | **no** — accepts an unknown entry |
| Ed25519 JWK + RFC 7638 thumbprint | yes | absent |
| preserves the presented protected header bytes | yes | n/a |

go-jose wins on the last three. The `crit` result is a quality signal rather
than something relied on — see *On `crit`* above — and the JWK support
matters directly, since `cnf.jwk` is how a parent names its child's key.
