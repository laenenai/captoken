# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

## Scope and status

This module is **pre-1.0**. The API may change, and it has not had an external
security review. Do not deploy it where a failure would be material without
reading `CHARTER.md` — in particular its stated non-contents, which are the
guarantees this module explicitly does **not** make.

## Release and review policy

- Every release requires **two-person review**: one author and one reviewer
  other than the author. Release notes, the changelog and the API diff are part
  of that review.
- Release tags are **signed** and created only from a commit that passed
  `mise run check`. `mise run release-check` runs `gorelease` from a clean
  checkout before tagging.
- Security reports are acknowledged privately, triaged for severity, and fixed
  on a private branch before disclosure. The maintainers will agree a disclosure
  date with the reporter and publish an advisory with the fixed version.
- **An external security audit is required before v1.0.** Until then, treat the
  module as reviewed by its maintainers and the conformance suite, not by an
  independent auditor.
- `go.mod`'s Go version is the minimum supported toolchain. CI runs the
  pinned toolchain and a separate minimum-version job.

## What the conformance suite proves, and what it does not

Each port in this module ships a conformance suite that every adapter must
pass, and the suite — not the interface — is the authoritative description of
the contract. Security invariants have their own named subtests. With
`Wiring.FullAdoption` set, a missing reservation or nonce adapter is a test
failure rather than a skip; without it, the skipped stateful/nonce coverage is
explicit and cannot be mistaken for full adoption.

The suite proves the *contract*. It cannot prove *enforcement* that belongs to
something outside this process: a database's row-level security, a key
manager's access policy, an operator's privilege separation. Those are verified
by integration tests against the real dependency where one exists, and are
otherwise the deployment's responsibility. Where that line falls is stated in
the package documentation rather than left to be assumed.

## The three things this module cannot enforce, stated plainly

Each is a real boundary rather than a caveat on the prose above, and each has
a documented owner.

**1. The stateful caveats' ordering discipline.** `max_uses`,
`expires_after_first_use` and `max_bytes_transferred` read counters that this
module never advances. The caller must read the counter, verify, perform the
operation, and persist the advance **only on success, inside the same
transaction**. That ordering is a property of the caller's transaction and no
library can impose it. What this module does enforce is that verification only
ever reads, so a failed operation cannot consume a use or a byte allowance —
`StatefulCaveatsDoNotAdvanceOnFailure` in the conformance suite is the test.

**2. A third-party verifier's completeness.** The published format
(`docs/wire-format.md`) makes a *soundness* guarantee that is structural:
nothing a verifier cannot evaluate can reach it, because the only conditions
needing data a verifier may not have live on a token type whose `aud` keeps it
away from anyone but the issuer's reservation service. *Completeness* is
contractual instead: a verifier must implement the closed caveat vocabulary and
must refuse a kind it does not recognize, and an issuer must not name a
non-conforming verifier in `aud`. `aud` is the enforcement point, and it is the
one claim every mainstream JWT library checks correctly.

**3. What a caveat describes, versus what is true.** `watermark` narrows which
rendition a request may name; it cannot and does not assert that the bytes
stored there are watermarked. `required_readiness` compares a label the caller
supplies. `allowed_content_types` matches the **sniffed** type of the bytes on
the wire — a caller that passes a declared header instead has defeated the
caveat, and no token can detect that. Each of these is stated at the
declaration it affects.

## Reporting a refusal that explains itself

A refusal from this module names nothing: not the check that failed, not a
claim, not a value. If you find a path where a refusal leaks any of those,
that is a reportable defect even though nothing is decrypted or forged by it —
an oracle is cheap to search and the whole error discipline exists to deny
one.

## Two rendering holes that redaction cannot close

`KeyPair`, `Minter`, `MinterConfig` and `Minted` implement all four of
`fmt.Stringer`, `fmt.Formatter`, `json.Marshaler` and `slog.LogValuer`, so no
verb, marshaller or log handler can be made to print a private key or a
presentation token out of them. Two holes remain, and they remain because no
implementation closes them rather than because nobody looked.

**`%p`, and any other bad verb.** `fmt` sets its internal erroring flag before
it describes the operand, so `handleMethods` returns without consulting any
interface and the operand is reflected instead. `fmt.Sprintf("%p", minter)` on
a value receiver therefore prints the struct. Nothing a type can implement
changes that. Holding material behind a pointer field mitigates it; this module
does not, because the four types are small value types a caller passes by
value.

**A bare `ed25519.PrivateKey`.** `GenerateKey` returns a `KeyPair`, and
`Minted.HolderKey` and `MinterConfig.RootKey` are fields on redacted types —
but once a caller assigns one of those to a variable of its own, it holds a
stdlib `[]byte` with no type identity of ours to hang a method on, and `%v` on
it prints every byte. A named wrapper type was considered and rejected: the
module's private keys are always *reached through* one of our four types, so
the methods belong there, and a wrapper would force a conversion at every
signing call site for no gain. This is the same line `tenancy` draws in the
other direction — its DSNs were bare `string` fields with nothing to hang a
method on, so there a wrapper type was the fix.

A path where this module itself renders a key or a token outside these two
cases is a reportable defect.
