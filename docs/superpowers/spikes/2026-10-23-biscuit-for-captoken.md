# Spike: should `captoken` be built on Biscuit?

**Date:** 2026-10-23
**Scripts:** [`2026-10-23-biscuit-probe/`](./2026-10-23-biscuit-probe/)
**Transcripts:** [`2026-10-23-biscuit-probe/transcripts/`](./2026-10-23-biscuit-probe/transcripts/)

Four questions about adopting Biscuit in place of the bespoke 3,862-line
implementation at `cas/internal/token/`. Every verdict below was produced by
running `biscuit-go` against a real token; nothing is taken from the Biscuit
specification or the library's README.

## What was tested on

| Component | Version |
|---|---|
| Go | `go1.25.6 darwin/arm64` |
| Biscuit Go library | `github.com/eclipse-biscuit/biscuit-go/v2 v2.2.2` (tagged 2026-10-14) |
| Biscuit spec level implemented | **schema version 3** (`biscuit.MaxSchemaVersion == 3`) |
| Licence | Apache-2.0 |
| Transitive deps (non-test) | `google.golang.org/protobuf v1.36.12`; `github.com/alecthomas/participle/v2 v2.1.4` (only for the `parser` subpackage) |
| Reference vectors | `samples/data/current/*.bc`, 38 files, produced by the **Rust** implementation |
| Bespoke baseline | `cas/internal/token`, 3,862 lines, tests green, 72.2% statement coverage |

The bespoke baseline was run as a control (`go test -cover ./internal/token/`
→ `ok … coverage: 72.2% of statements`). Its 2,065 lines of tests are the
yardstick for the cost section.

---

## Q1 — Can Biscuit make a stateful caveat fail *closed* across the interop boundary?

**Yes, and it does so by construction. This is the question that decides the
design, and the answer is favourable.**

The hazard was: if offline caveats are expressed in Biscuit's Datalog, a
third-party verifier (a Java client, say) evaluates them correctly and is
*blind* to the stateful ones — `MaxUses`, `ExpiresAfterFirstUse`,
`MaxBytesTransferred` — because those need a server-side counter read. Such
a verifier would accept a token whose uses are exhausted. A fail-open.

Biscuit removes the hazard because a `check` is not a statement a verifier
can *skip*. It is a Datalog query that must return at least one result. If
the predicate it queries has no matching fact in the authorizer's world, the
query returns empty and the check **fails**. Ignorance and refusal are the
same outcome, so a verifier cannot be blind to a check — only refused by it.

### The token

The authority block carries one ordinary offline caveat and one stateful
caveat modelled as a check over a fact only the authorizing server can
supply (`q1_test.go`):

```
right("doc:123", "read");
check if resource($r), operation($op), right($r, $op);
check if uses_remaining($n), $n > 0;
```

### Both outcomes, as run (`transcripts/TestQ1.txt`)

| # | Authorizer | Outcome |
|---|---|---|
| A | `resource("doc:123"); operation("read"); uses_remaining(3); allow if true;` | **AUTHORIZED** |
| B | …`uses_remaining(0)`… | **REFUSED** |
| C | `resource("doc:123"); operation("read"); allow if true;` — **no `uses_remaining` fact at all** | **REFUSED** |
| D | fact supplied but **no policy** | **REFUSED** |

Verbatim, for C — the third-party verifier that does not know the counter
exists:

```
--- C. third-party verifier, BLIND to the counter (no uses_remaining fact)
    => REFUSED
    err: biscuit: verification failed: failed to verify block 0 check #1: check if uses_remaining($n), $n > 0
```

A verifier that does not supply the fact **fails the check rather than
skipping it**. That is exactly the property asked for. Case D adds a second
layer: `Authorize()` returns `ErrNoMatchingPolicy` when no `allow if` policy
matches, so a verifier that evaluates nothing authorizes nothing.

### The corollary that matters just as much: the bearer cannot forge the fact

A fail-closed check over a server-supplied fact is only worth having if the
*bearer* cannot supply the fact themselves. Biscuit's block isolation
delivers this. In `authorizer.go`, authority checks are evaluated against
`v.world` (authorizer facts + authority facts), while each attenuation
block's facts are added only to a per-block `v.world.Clone()`. A fact
asserted in a later block therefore never reaches an earlier block's check.

Three forgery attempts, all refused (`transcripts/TestQ1.txt`):

| # | Attack | Outcome |
|---|---|---|
| E | bearer appends a block asserting `uses_remaining(999)`; stateful check is in the **authority** block | **REFUSED** |
| F | stateful check is in **attenuation block 1**; verifier supplies no fact | **REFUSED** |
| G | stateful check in block 1; bearer appends **block 2** asserting `uses_remaining(999)` | **REFUSED** |

```
--- G. block-1 stateful check, LATER block-2 forges uses_remaining(999)
    => REFUSED
    err: biscuit: verification failed: failed to verify block #1 check #0: check if uses_remaining($n), $n > 0
```

So the offline/stateful split **can** be made safe inside one token. The
recommendation below rests on this.

### Three sharp edges in the server-supplied-fact model

Q1's answer is yes, but the mechanism has edges `captoken` must own
(`transcripts/TestQ8.txt`).

**Type confusion and arity errors fail closed.** Good news, and not
guaranteed a priori:

| Injected fact | `check if uses_remaining($n), $n > 0` |
|---|---|
| `uses_remaining(3)` | AUTHORIZED |
| `uses_remaining("unlimited")` | REFUSED |
| `uses_remaining(true)` | REFUSED |
| `uses_remaining()` | REFUSED |
| `uses_remaining(0, 5)` | REFUSED |

**Datalog checks are existential, so duplicate facts fail OPEN.** This is
the one genuine hazard found:

```
uses_remaining(0) AND uses_remaining(5) both injected          => AUTHORIZED
```

A check is satisfied if *any* matching fact exists. An authorizer that
injects a stale counter alongside the true one authorizes the request. The
bespoke design cannot express this bug — `Request.UsesBefore` is a single
`int` field. In Biscuit, "exactly one fact per stateful predicate per
authorization" becomes an invariant `captoken` must enforce in its own
authorizer-construction API, not something the library enforces.

**There is no negation.** `check if !revoked();`, `check if not revoked();`
and `reject if revoked();` all fail to parse in biscuit-go v2.2.2. Every
condition must be phrased positively (`check if not_revoked();`), which is
fortunately also the fail-closed direction.

---

## Q2 — Can the existing caveat vocabulary be expressed?

All sixteen caveat kinds in `caveat_types.go`, plus the four `Block` fields
`CheckAll` enforces. Three classes: **(C)** a pure Biscuit check over facts
a verifier can derive locally; **(F)** expressible only with a
server-supplied fact; **(N)** not expressible.

Every row was executed (`transcripts/TestQ2.txt`).

| Caveat | Class | Datalog form, and what was observed |
|---|---|---|
| `ExpiresAt` | C | `check if time($t), $t <= 2026-10-23T12:00:00Z;` — native `Date` terms. Before expiry AUTHORIZED, after REFUSED, **`time()` fact absent REFUSED**. Clock-skew tolerance is *not* native (see below). |
| `NotBefore` | C | mirror image, `$t >= …`. |
| `ExpiresAfterFirstUse` | F | needs `first_used_at`, a counter read. `check if first_used_at($f), time($t), $t <= $f + 3600;` |
| `MaxUses` | F | `check if uses_remaining($n), $n > 0;` — the Q1 shape. |
| `ResourceScope` | C* | `check if resource($r), $r.starts_with("tenant/t1/fs/a/doc/");` In-scope AUTHORIZED, sibling fileset REFUSED. **But see the prefix-boundary hazard below — this is the one that needs care.** |
| `PermissionSet` | C | `right($r, $op)` facts in the authority block + `check if resource($r), operation($op), right($r, $op);`. |
| `MaxContentLength` | C | `check if content_length($n), $n <= 1048576;` 1 MiB AUTHORIZED, +1 REFUSED, **fact absent (chunked, unknown length) REFUSED** — the bespoke `-1` fail-closed sentinel is reproduced by *absence*, which is cleaner. Note `content_length(-1)` does not even parse (below). |
| `AllowedContentTypes` | C | `check if content_type($t), ["application/pdf","image/png"].contains($t);` Sniffed `application/pdf` AUTHORIZED; **`"application/pdf; charset=../../x"` REFUSED**; fact absent REFUSED. Set `.contains` is exact-match, so parameter smuggling is rejected with no special-case logic — same reason the bespoke version works. The "match the sniffed type, never the declared header" contract is *not* enforceable by the token; it stays a caller obligation either way. |
| `MaxBytesTransferred` | F | `check if bytes_before($b), content_length($c), $b + $c <= 1000;` Overflow is safe: `datalog.Add` computes in `big.Int` and returns `ErrInt64Overflow`, which fails the expression and therefore the check. `bytes_before(9223372036854775807); content_length(1)` → **REFUSED**. The bespoke code's hand-rolled rearrangement is not needed. |
| `RequireAuthenticatedRecipient` | F | `check if authenticated_recipient();` presence only. |
| `RequiredReadiness` | F | `check if readiness($s), ["ready","indexed"].contains($s);` `ready` AUTHORIZED, `ingesting` REFUSED. Needs a document-state read, so F not C. |
| `RequireDeclaredDigest` | F | `check if declared_digest($d);` declared AUTHORIZED, absent REFUSED. |
| `ClientCIDR` | **F (was N)** | **No native IP or CIDR term or operator exists.** All three plausible spellings fail to parse. String prefix is semantically wrong — `10.100.0.5` matches `starts_with("10.1")` but is outside `10.16.0.0/12`, and that case **AUTHORIZED**. A regex works for that example but is not a general CIDR matcher. The correct form moves the match server-side: `check if client_in_cidr("10.16.0.0/12");` with the server doing `netip.Prefix.Contains` and asserting the fact — fact present AUTHORIZED, absent **REFUSED**. So it is expressible, but only as a server-supplied fact, which costs it offline verifiability. |
| `DelegationDepth` | F | Block count is not visible to Datalog. `check if chain_depth($d), $d <= 2;` with a server-supplied fact: present AUTHORIZED, absent REFUSED. **Footgun:** `Biscuit.BlockCount()` returns `len(container.Blocks)`, i.e. **0 for a single-block token** — it excludes the authority block. The bespoke `Request.ChainDepth` doc comment warns about exactly this off-by-one; the library's accessor is off by one in the *other* direction from the bespoke convention. |
| `ProcessorAudience` | C | `check if processor($p), $p == "sha256:aabbcc";` match AUTHORIZED, other processor REFUSED, absent REFUSED. |
| `Watermark` | C | `check if slot_path($s), $s == "renditions/watermarked";` rendition AUTHORIZED, original REFUSED. Expresses exactly as much as the bespoke version does — which slot path may be named, not that the bytes there are watermarked. |
| `Block.NotBefore` / `.ExpiresAt` | C | same as the caveats. |
| `Block.Permissions` | C | `right()` facts. |
| `Block.Resources` | C* | as `ResourceScope`. |

**Nothing is class N.** Sixteen of sixteen caveat kinds are expressible.
Seven are pure offline checks; nine need a server-supplied fact, and all
nine fail closed when it is absent.

### The `ResourceScope` prefix-boundary hazard

`domain.ResourceRef.Contains` is hierarchical containment over a structured
reference (kind, tenant, fileset path, document, slot path, slot index).
Datalog has no structured terms — only `.starts_with` on a flattened string.
That works, but it introduces a failure mode the bespoke version does not
have:

```
scope 'fs/a' leaks into 'fs/ab' (sibling!)                     => AUTHORIZED
```

A scope string not terminated at a path separator matches a *sibling*. The
bespoke `Contains` compares `FilesetPath` element by element and cannot do
this. Flattening a `ResourceRef` to a string means `captoken` must guarantee
a canonical, separator-terminated, separator-escaped encoding — and that
encoding becomes security-critical in a way the structured comparison never
was.

### Parser limits found (`transcripts/TestQ2.txt`)

```
content_length(-1);                 PARSE ERROR: unexpected token "-" (expected ")")
content_length(0 - 1);              PARSE ERROR: unexpected token "-" (expected ")")
slot_index(-1);                     PARSE ERROR: unexpected token "-" (expected ")")
```

**Negative integer literals do not parse in biscuit-go v2.2.2.** Any caveat
whose vocabulary includes a negative sentinel (`ContentLength == -1`,
`SlotIndex == -1`) must be re-modelled as the *absence* of a fact. That is
fine — it is the fail-closed direction — but it is a redesign, not a
translation.

### Clock skew is not native

The bespoke code applies ±60s symmetrically in `ExpiresAt`, `NotBefore`,
`ExpiresAfterFirstUse` and `checkBlockFields`. Biscuit has no notion of
tolerance:

```
now = expiry + 30s, no tolerance applied                       => REFUSED
now = expiry + 30s, authorizer subtracts 60s tolerance         => AUTHORIZED
```

The tolerance must be applied by whoever constructs the `time()` fact, or
baked into the bound at mint time. Either way `captoken` owns it, and a
consumer that builds its own authorizer gets no tolerance unless `captoken`'s
API supplies it. That is a fail-*closed* omission (tokens expire 60s early),
so it degrades safely.

### The error message is an oracle

This is a direct conflict with the bespoke stance, and it is not
configurable (`transcripts/TestQ2.txt`):

```
biscuit: verification failed: failed to verify block 0 check #0:
  check if processor($p), $p == "sha256:SECRET-THUMBPRINT-aabbccddeeff",
  failed to verify block 0 check #1: check if client_in_cidr("10.16.0.0/12")
```

`ErrCaveatNotSatisfied`'s doc comment is explicit: *"a verifier that explains
why a request was refused hands an attacker a dimension to search along."*
`Authorize()` names every failing check by index **and echoes its full text,
including embedded literal values** — here a certificate thumbprint and an
internal CIDR. `captoken` must discard this error and substitute an opaque
sentinel, and must never log it where a request path can observe it. The
information is also genuinely useful for debugging, so the API needs two
paths and the safe one must be the default.

---

## Q3 — The library's actual state

### There is exactly one Go implementation, not three

The three candidate paths are **one GitHub repository that has been
transferred twice**. The GitHub API resolves both old paths to the same
repository id:

```
$ curl -sSI https://api.github.com/repos/flynn/biscuit-go        | grep -i location
location: https://api.github.com/repositories/230325508
$ curl -sSI https://api.github.com/repos/biscuit-auth/biscuit-go | grep -i location
location: https://api.github.com/repositories/230325508
```

`flynn/biscuit-go@v1.0.0` and `biscuit-auth/biscuit-go@v1.0.0` are the same
commit, both timestamped `2022-02-18T21:43:43Z`, and `flynn`'s `go.mod`
declares its path as `github.com/biscuit-auth/biscuit-go`. The rename to
`eclipse-biscuit` landed in v2.2.1 (CHANGELOG: *"Change the repository
organisation to `eclipse-biscuit` (#175)"*).

**The old import path no longer works.** This is a hard fact, not a style
preference:

```
$ go build   # importing github.com/biscuit-auth/biscuit-go/v2
go: pathtest imports
	github.com/biscuit-auth/biscuit-go/v2: …@v2.2.2: parsing go.mod:
	module declares its path as: github.com/eclipse-biscuit/biscuit-go/v2
	        but was required as: github.com/biscuit-auth/biscuit-go/v2
```

**Current module path: `github.com/eclipse-biscuit/biscuit-go/v2`, latest
`v2.2.2`.** Published versions: v2.0.0, v2.1.0, v2.2.0, v2.2.1 (retracted),
v2.2.2.

### Maintained, and recently

Last push `2026-10-19` (four days before this spike); last five commits
span 2026-10-14 to 2026-10-19. 90 stars, 24 open issues, not archived,
Apache-2.0 (confirmed both from the GitHub API and the `LICENSE` file in the
module). v2.2.2 was cut nine days before this spike.

**v2.2.1 is retracted in `go.mod`**, and the reason is worth reading:

```
// Biscuit.Authorizer silently ignores its options, see ./CHANGELOG.md
retract v2.2.1
```

A verification entry point that silently dropped its options, shipped and
caught within days. That is the right outcome (retracted, not patched over),
but it is a data point about the library's maturity in exactly the area
`captoken` would depend on.

### Builds cgo-free, light dependency weight

```
$ CGO_ENABLED=0 go build ./...                              → OK
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...       → OK
```

Builds and cross-compiles cgo-free on go 1.25.6. The core package's only
third-party dependency is `google.golang.org/protobuf`; `participle/v2` is
pulled in only by the `parser` subpackage, which is needed to compile
Datalog source strings. `testify` and `goleak` are test-only.

### No advisories

```
$ govulncheck ./...
No vulnerabilities found.
Your code is affected by 0 vulnerabilities.
```

44 advisories exist in "modules you require", and **all 44 are against
`stdlib@go1.25.6` itself** (GO-2026-6809, GO-2026-6617, …), none against
biscuit-go or its dependencies. Verified with `-show verbose`: every entry
is labelled `Standard library`. Unrelated to this decision, but it does mean
the toolchain wants a bump to go1.26.10.

### Cross-language interop: verified in one direction, not the other

**Rust → Go: verified.** The 38 `.bc` vectors in the library's `samples/`
directory are produced by the Rust reference implementation. The conformance
test passes (`transcripts/samples.txt`), and a stronger check — unmarshal
each vector with biscuit-go and re-serialize it (`transcripts/TestQ3.txt`):

```
### Rust-generated vectors through biscuit-go (38 files)
  byte-identical re-serialization: 20
  parsed but re-serialized differently: 0
  NOT PARSEABLE by biscuit-go: 18
```

Twenty Rust-produced tokens round-trip **byte-for-byte** through
biscuit-go's reader and writer, and zero parse-then-differ. That is strong
evidence of wire compatibility for the subset biscuit-go implements.

**Go → Rust/Java: could not be run here, and I am not going to assume it.**
No Rust toolchain is installed (`cargo` and `rustc` both absent), and
`/usr/bin/java` is the macOS stub with no JRE behind it (`Unable to locate a
Java Runtime`). `biscuit-java 4.0.1` is available on Maven Central
(`org.biscuitsec:biscuit`, HTTP 200) and `curl` reaches it, but without a
JVM or Maven it cannot be exercised. The byte-identical round-trip above is
the best available proxy and it is one-directional: it shows Go *reads and
writes* the bytes Rust produces, not that Rust accepts bytes Go originates.

### The real interop finding: biscuit-go is behind the spec

This matters more than the missing JVM. Of the 18 unparseable vectors, two
are deliberately corrupt (`test003_invalid_signature_format` and
`test004_random_block`), two use secp256r1 keys biscuit-go does not support,
one needs v3.1 expressions — and **thirteen are simply a newer schema
version than biscuit-go implements**:

```
test024_third_party.bc           block version: 4 > library version 3
test025_check_all.bc             block version: 4 > library version 3
test026_public_keys_interning.bc block version: 4 > library version 3
test027_integer_wraparound.bc    block version: 4 > library version 3
test028_expressions_v4.bc        block version: 4 > library version 3
test029_reject_if.bc             block version: 6 > library version 3
test030_null.bc                  block version: 6 > library version 3
test031_heterogeneous_equal.bc   block version: 6 > library version 3
test032_laziness_closures.bc     block version: 6 > library version 3
test033_typeof.bc                block version: 6 > library version 3
test034_array_map.bc             block version: 6 > library version 3
test035_ffi.bc                   block version: 6 > library version 3
test038_try_op.bc                block version: 6 > library version 3
```

`biscuit.MaxSchemaVersion == 3`, while the reference vectors reach version
**6**. biscuit-go also explicitly skips `test013_block_rules` and
`test017_expressions` with the comment *"all these use features from v3.1+,
which are not supported yet"*.

The interop consequence is **asymmetric**, and it cuts the favourable way
for the Q1 story but the unfavourable way for the ecosystem story:

- A token Go *mints* is schema v3, which newer Rust and Java
  implementations read (v3 is within their supported range).
- A token a Java or Rust client mints using v4+ features — **third-party
  blocks among them** (`test024_third_party`) — biscuit-go **cannot parse at
  all**.

So "Eclipse Foundation project with six implementations" is true of Biscuit
the specification and substantially less true of biscuit-go the library.
Adopting it means pinning the whole system to Biscuit v3 semantics and
accepting that `captoken` is the slowest implementation in the ecosystem.

### Token size: no penalty

For a realistic 15-caveat CAS signed-download link
(`transcripts/TestQ7.txt`, and a matching bespoke measurement):

| | 1 block, sealed | + 1 attenuation |
|---|---|---|
| Biscuit (base64url chars) | 1,399 | 1,627 |
| Bespoke (`Token.String()`) | 1,304 | 1,721 |

Biscuit is 7% larger for a single block and 5% *smaller* once attenuated —
its symbol-table interning amortises across blocks where the bespoke format
repeats strings. Both sit uncomfortably close to the ~2,000-char practical
URL budget, but that is a pre-existing problem and Biscuit does not worsen
it.

---

## Q4 — Revocation and single-use

Both are online checks in the charter. Biscuit **composes** with a
server-side record rather than duplicating it, and it does one part of the
job better than the bespoke design.

### `RevocationIds()` is the block signatures, one per block

```go
func (b *Biscuit) RevocationIds() [][]byte {
	result := make([][]byte, 0, len(b.blocks)+1)
	result = append(result, b.container.Authority.Signature)
	for _, block := range b.container.Blocks {
		result = append(result, block.Signature)
	}
	return result
}
```

64 bytes each (`transcripts/TestQ4.txt`). The important observed property:

```
root (1 block)              ids=1  [0] c810564245c222d4…
attenuated (2 blocks)       ids=2  [0] c810564245c222d4…  [1] 962d3fefa3b17d77…
sealed                      ids=2  [0] c810564245c222d4…  [1] 962d3fefa3b17d77…
after serialize/deserialize ids=2  [0] c810564245c222d4…  [1] 962d3fefa3b17d77…
```

**The ancestor's id is byte-identical in every descendant.** That is chain
revocation for free, and exactly what the charter asks for: revoke the root's
id and every token attenuated from it dies, because every descendant still
presents that id. The bespoke design has no equivalent — `Fingerprint(t)`
hashes the *whole* token, so revoking a parent does not revoke its children
and chain revocation has to be built separately on top.

Ids are stable across `Serialize`/`Unmarshal` and across `Seal`. They are
**not** deterministic across two independent `Append` calls with identical
block content (each `Append` generates a fresh next-keypair, so the
signature differs) — which is correct behaviour for a revocation identifier:
two separately issued tokens must be separately revocable.

### Revocation ids are a *safer* single-use key than the bespoke `Fingerprint`

`Request.UsesBefore`'s doc comment is emphatic that the counter must be keyed
on `Fingerprint(t)` and never on the presented string, because the presented
bytes are not unique for a semantic token. The same hazard exists in Biscuit
— protobuf tolerates unknown trailing fields — and I confirmed it, along with
the fact that revocation ids are immune (`transcripts/TestQ6.txt`):

```
original          ( 219 bytes) ids: e3a8db301303b489
+ unknown pb field( 224 bytes) ids: e3a8db301303b489
  bytes differ from original: true
```

A byte-permuted token (5 bytes of unknown protobuf field appended) still
verifies under the root public key and yields the **same** revocation id. So
`RevocationIds()` is a canonical identity with no re-encoding step — the
bespoke `Fingerprint` has to re-encode the decoded chain to get the same
guarantee, and that re-encoding is itself a correctness surface.

### What Biscuit does *not* do

It has no opinion whatsoever about where revoked ids are stored or how
single-use is recorded. `RevocationIds()` returns bytes; `Authorize()` never
consults them. So:

- **Revocation** composes cleanly: the server reads the ids, checks them
  against its revocation table, and refuses out-of-band. No duplication of
  the server-side record — Biscuit supplies the *key*, the server supplies
  the *answer*.
- **Single-use** is the same shape, and gains the Q1 fail-closed property if
  it is *also* expressed as a check: `check if not_revoked();` with the
  server asserting `not_revoked()` only after its table lookup passes. Fact
  present → AUTHORIZED, fact absent → **REFUSED**
  (`transcripts/TestQ4.txt`). A third-party verifier that cannot reach the
  revocation table therefore refuses rather than accepting a revoked token.

**One structural limit:** a token cannot name its own revocation id inside
one of its own checks. The id *is* the block's signature, which does not
exist until after the block carrying the check has been signed. So the
server must look the id up externally; it cannot be self-referential.

### Transaction ordering is unchanged

`TestStatefulCaveats_DoNotAdvanceWhenTheOperationFails` encodes the rule
that a caveat reads a counter but never advances it, and that the advance is
persisted only after the operation succeeds, inside the same transaction.
Nothing about Biscuit changes this; it remains entirely the consumer's
responsibility, exactly as `Request`'s doc comment describes. Adopting
Biscuit neither helps nor hurts here.

---

## Two properties I expected to lose and did not

### Chain truncation is already resisted

The bespoke `Token.Proof` field, and the long proof in `envelope.go`'s doc
comment, exist to stop a bearer presenting a *prefix* of the chain and
recovering the ancestor's wider authority. Biscuit resists this already
(`transcripts/TestQ5.txt`). Authority grants read+write, attenuation narrows
to read-only, then the narrowing block is stripped at the protobuf layer:

```
honest 2-block sealed token, write           => REFUSED (block #1 check #0)
truncated to 1 block, sealed proof kept      => REFUSED at Authorizer: biscuit: invalid last signature
truncated UNSEALED token (bearer holds next secret)
                                             => REFUSED at Authorizer: biscuit: invalid last signature
truncated + re-sealed with held next secret  => REFUSED at Authorizer: biscuit: invalid last signature
```

All three variants refused, including the strongest one where the bearer
holds the next secret key for the block being dropped. Note the refusal
comes from `Authorizer(pub)`, **not** from `Unmarshal` — `Unmarshal` does no
signature checking at all. Any `captoken` API must therefore make it
impossible to act on an unmarshalled-but-unauthorized token.

### Attenuation cannot widen, and the `Narrows` machinery becomes unnecessary

`caveat_types.go` implements `Narrows` on all sixteen kinds, and
`TestNarrows_AllSixteenKindsBothDirections` plus
`TestNarrows_CrossKindAlwaysRefuses` police it. Its purpose is to let the
minter refuse an attenuation that would widen a caveat.

In Biscuit this is structural. An appended block can only *add* checks, and
its facts do not reach earlier blocks' checks or the policy evaluation
(`transcripts/TestQ2.txt`):

```
bearer appends right("doc:999","write")  => REFUSED
    (block fact did not reach the authority check or policy)
append to a SEALED token                 => REFUSED
    biscuit: append failed, token is sealed
```

Monotonic narrowing is a property of the evaluation model, not of a
comparison the minter has to get right sixteen times. This is the single
largest genuine simplification on offer.

### One property that is genuinely worse: key custody

`envelope.go` calls this out as a deliberate departure, and it was right to:

```
UNSEALED token: proof carries NextSecret, 32 bytes of PRIVATE key
wire-only recipient attenuates an unsealed token  => SUCCEEDED (key was in the bytes)
SEALED token: proof carries FinalSignature, 64 bytes (no key material)
```

An unsealed Biscuit **serializes the next signing private key**, and a
recipient who has only ever seen the bytes can attenuate it. In the bespoke
design no private key is ever part of a token's serialized form, full stop,
so a wire recipient can *never* attenuate regardless of sealing.

For Biscuit this is intended (it is how offline delegation works), but it
means `Seal` moves from a nice-to-have to a **load-bearing invariant**: any
`captoken` token that reaches a party who must not attenuate has to be
sealed, and an unsealed token is key material. `captoken`'s API should make
the unsealed form hard to serialize by accident — ideally it should not be
reachable at all from the public surface.

---

## Recommendation: hybrid, with the line drawn at the wire format

**Build `captoken` on Biscuit for the envelope, and keep the bespoke
caveat-semantics layer as `captoken`'s own typed API above it.**

Not "adopt Biscuit" and not "keep bespoke". The reasoning follows the
evidence:

**Adopt Biscuit's envelope** — signing, chaining, attenuation, sealing,
serialization, revocation ids. This replaces `envelope.go` (434) and
`codec.go` (485) outright, about 919 lines plus 898 lines of their tests.
What is bought:

- Public-key verification, which is the original motivation. Confirmed:
  `Authorizer(pub)` takes a 32-byte `ed25519.PublicKey`, and a foreign key
  gives `biscuit: invalid signature`. CAS, kgs and acre verify with the
  public key and never hold the signing secret.
- Chain revocation for free, via the ancestor id appearing in every
  descendant — which the bespoke design does not have at all and would have
  to grow.
- A canonical single-use key (`RevocationIds()`) with no re-encoding step.
- Truncation resistance and monotonic attenuation as properties of the
  model rather than code to be kept correct.
- Someone else's protobuf codec, hardened by a published cross-language
  conformance suite, instead of a hand-rolled length-prefixed format whose
  `readCount` allocation guard is `captoken`'s to maintain forever.

**Keep the caveat layer bespoke, above Biscuit.** `captoken` exposes typed
Go caveats — `MaxUses(3)`, `ClientCIDR(prefix)`, `ResourceScope{…}` — and
compiles them *down* to Biscuit checks at mint time, and compiles a typed
`Request` *down* to a set of authorizer facts at verify time. The Datalog is
an implementation detail of `captoken`, never a public surface. What this
preserves:

- The sixteen caveats stay typed, individually testable Go values. The 2,065
  lines of tests survive as tests of the compiler's *output semantics*
  rather than being thrown away.
- The error discipline is restorable. `captoken` discards Biscuit's
  oracle-shaped error and returns `ErrCaveatNotSatisfied`.
- The "exactly one fact per stateful predicate" invariant has one place to
  live: the authorizer-construction API. Nobody hand-writes a fact set, so
  nobody can inject a stale `uses_remaining` alongside the true one.
- Clock-skew tolerance has one place to live.
- The `ResourceRef` → string encoding has one place to live, and
  separator-termination is enforced there once rather than trusted at every
  call site.

**Where exactly the line falls.** `captoken`'s module then contains:

| | |
|---|---|
| **Gone** (Biscuit's) | block signing and chaining, the signed-bytes construction, sealing and the seal proof, truncation and reorder resistance, the wire codec and its bounds checks, token identity / revocation ids, attenuation monotonicity, the `Narrows` machinery on all sixteen kinds |
| **Kept, bespoke** | the sixteen typed caveat kinds and their semantics; `Request` and its typed fields; the caveat → Datalog-check compiler; the `Request` → authorizer-fact compiler; the canonical `ResourceRef` string encoding; clock-skew tolerance; the opaque-error boundary; the conformance suite (`suite.go`) |
| **New** | a `Verifier` that takes only an `ed25519.PublicKey`; an authorizer-fact builder that makes the duplicate-fact hazard unreachable; a pinned `MaxSchemaVersion` assertion so a library bump cannot silently change wire semantics |

The charter is unaffected: nothing here teaches `captoken` about principals,
groups or policy. `right()` facts carry opaque permission and resource
strings; subjects stay opaque ids. The module still answers only "is this
credential valid, and what does it permit?"

**The reviewed public API surface gets smaller, not larger.** The public surface loses
`Token`, `Block.PublicKey`, `Issue`'s returned private key, `Attenuate`,
`Seal`, `Verify`, `Parse`, `Fingerprint`, `encodableCaveat`, and the sixteen
`Narrows` methods. That is a charter win — the boundary mechanism rewards it.

### What would change this recommendation

Three things, none of which I found:

1. If Biscuit could not make stateful caveats fail closed. It can (Q1).
2. If a caveat were class N. None is (Q2).
3. If there were no maintained, cgo-free, Apache-2.0 Go implementation.
   There is exactly one, and it is maintained (Q3).

The one finding that *should* give pause is the schema-version gap:
biscuit-go implements v3 against a reference at v6, and cannot parse
third-party blocks. If `captoken`'s roadmap needs third-party blocks —
attestations signed by a key other than the root, which is the natural
Biscuit answer to "a processor vouches for something" — that feature is
**not available in Go today** and the recommendation would need revisiting.
It is worth confirming against the roadmap before committing.

---

## Honest cost: what adopting Biscuit loses

The 3,862 lines are not 3,862 lines of ceremony. Several encode bugs someone
already found and fixed, and a rewrite can reintroduce them. Listing them
plainly:

**Bugs the bespoke tests encode that Biscuit's model makes structurally
impossible** — safe to lose:

- `TestMaxBytesTransferred_RejectsOverflowingContentLength`. The int64
  overflow guard, with its careful rearrangement to never add two
  attacker-reachable values. `datalog.Add` uses `big.Int` and returns
  `ErrInt64Overflow`; verified refused.
- `TestVerify_RejectsTruncatedChain`,
  `TestVerify_TruncationCannotRestoreParentAuthority`,
  `TestVerify_RejectsReorderedBlocks`. Verified refused, all three variants.
- `TestReadCount_RejectsImplausibleCountsWithoutAllocating` and
  `TestParse_RejectsImplausibleElementCountWithoutHanging`. protobuf's own
  decoder owns this; the `minWireBytesPerElement` heuristic goes away.
- `TestNarrows_*` (three tests, 219 lines covering all sixteen kinds in both
  directions and cross-kind). Structural in Biscuit.
- `TestPermissionSetCaveat_DecodeThenEncodeNormalizesByteOrder` and
  `TestFingerprint_MatchesForSemanticallyIdenticalTokens`. The
  canonicalization hazard that motivated `Fingerprint`; `RevocationIds()` is
  canonical without it.

**Bugs the bespoke tests encode that Biscuit does NOT solve, and that must
be re-landed in the compiler layer** — this is the real cost:

- `TestAllowedContentTypes_RejectsParameterSmuggling` and
  `…MatchesSniffedTypeNotTheDeclaredHeader`. Set `.contains` is exact-match,
  so the smuggling case does fail — but the "sniffed, never declared"
  contract is a caller obligation that no token can enforce. The test must
  survive as a test of the fact-building API.
- `TestResourceScope_DocumentCaveatRejectsSiblingDocument` and
  `…SlotSeriesElementIsNarrowerThanSeries`. These get **harder**, not
  easier. Structured containment becomes string prefix matching, and I
  demonstrated the sibling leak (`fs/a` matching `fs/ab`) that the
  structured comparison cannot produce. This is a *new* bug class the
  rewrite introduces.
- `TestResourceScope_RefusesRatherThanIgnoresUnresolvedRequestResource` and
  `TestEncodeResource_RefusesUnresolvedRef`. The
  `ErrUnresolvedResourceRef` fail-closed guard, and the encode-side refusal
  that makes `decodeResource`'s "resolved by construction" premise true.
  Datalog has no concept of an unresolved ref; the guard must move into the
  encoder and be tested there.
- `TestDelegationDepth_RejectsUnpopulatedChainDepth`. The off-by-one trap,
  made *worse*: `BlockCount()` excludes the authority block, so it is off by
  one from the bespoke convention. A forgotten-field fail-open becomes a
  forgotten-field fail-open *plus* a units mismatch.
- `TestExpiresAt_RespectsSkewToleranceSymmetrically` and
  `TestNotBefore_…`. No native tolerance; must be re-landed in fact
  construction.
- `TestCaveats_NeverLeakSecretValues` and
  `TestVerify_NeverLeaksKeyMaterialOrTokenBytes`. **Actively regressed by
  the library.** `Authorize()` echoes failing check text including literal
  values; I reproduced a leaked certificate thumbprint. These two tests
  become more important, not less, and they now have to police a boundary
  against a dependency rather than against `captoken`'s own code.
- `TestUnknownCaveatKind_FailsClosed`, `TestCodec_UnregisteredCaveatKindFailsClosed`,
  `TestCheckAll_RejectsNilCaveatRatherThanPanicking`,
  `TestDecodeCaveat_RejectsNilResultFromDecoder`. The registry's
  fail-closed gate. Biscuit's answer is better (an unknown predicate has no
  fact, so its check fails) but it is a *different* mechanism, and the tests
  have to be rewritten rather than ported.
- `TestCheckAll_RejectsEmptyChain`. The empty-chain vacuous-pass bug — a
  genuinely subtle find. Biscuit's `ErrNoMatchingPolicy` covers the
  "nothing evaluated authorizes nothing" case, but the equivalent must be
  asserted afresh.

**New risks that did not exist before:**

- **The duplicate-fact fail-open.** `uses_remaining(0)` alongside
  `uses_remaining(5)` authorizes. A bug class the bespoke `int` field cannot
  express.
- **Unsealed tokens are key material.** 32 bytes of private key in the wire
  form, and a wire-only recipient can attenuate. `Seal` becomes
  load-bearing.
- **`Unmarshal` does not verify.** Signature checking happens in
  `Authorizer(pub)`. An API that lets a caller inspect an unmarshalled
  token's contents before authorizing is a bypass waiting to be written.
- **A third-party dependency in the trust path**, whose immediately previous
  release was retracted because `Authorizer` silently ignored its options —
  a fail-open in the exact entry point `captoken` would depend on.
- **Pinned to Biscuit v3**, with third-party blocks unavailable in Go and no
  control over when that changes.

**Net.** The hybrid retires roughly 900 lines of envelope and codec plus
their ~900 lines of tests, and about 220 lines of `Narrows` machinery plus
its tests — call it 2,000 lines, with genuinely better security properties
in three places (chain revocation, canonical identity, structural
monotonicity) and the public-key verification that motivated the question.
It keeps the ~2,000 lines of caveat semantics and their tests
(`caveat.go` 251 + `caveat_types.go` 880 + `caveat_test.go` 885), where the
hard-won bugs actually live. Of the roughly twenty tests that encode real
bugs, about eight become structurally impossible, about ten must be
re-landed against a new mechanism, and two (`NeverLeakSecretValues`,
`NeverLeaksKeyMaterial`) get *harder* because the dependency actively works
against them.

That is a good trade, but it is a trade, and the migration must be
test-first: the existing 2,065 lines of tests are the specification the
Biscuit-backed implementation has to satisfy before `cas` switches over.
The conformance suite in the charter is the right mechanism for exactly
this — `cas` counts as adopted when `captoken`'s suite runs green against
its own wiring, not when the envelope compiles.

---

## Things that surprised me

- **Biscuit fails closed on unknown checks for free**, and it is the same
  mechanism as "no fact, no match". I expected to have to argue for a
  convention; it is a property of Datalog evaluation.
- **Block isolation is strict.** A later block's facts reach neither an
  earlier block's checks nor the policy evaluation. Without this, the whole
  server-supplied-fact design would be forgeable by the bearer, and the
  recommendation would be "keep bespoke".
- **Negative integer literals do not parse.** Not a semantic limit, just a
  grammar gap, and it quietly forces every `-1` sentinel to be re-modelled.
- **`BlockCount()` excludes the authority block**, returning 0 for a
  one-block token — the exact off-by-one the bespoke `ChainDepth` comment
  warns about, in the opposite direction.
- **The error message leaks caveat literals.** I went looking for an option
  to suppress it and there is none.
- **Revocation ids are better than `Fingerprint`**, and I did not expect the
  ancestor's id to appear byte-identical in every descendant. Chain
  revocation, which the bespoke design would have had to build, is already
  there.
- **biscuit-go is three schema versions behind the reference vectors.** The
  "six implementations, Eclipse Foundation" framing is about the
  specification; the Go library is the laggard, and third-party blocks are
  not available in it at all.
