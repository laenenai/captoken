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

## What the conformance suite proves, and what it does not

Each port in this module ships a conformance suite that every adapter must
pass, and the suite — not the interface — is the authoritative description of
the contract. Security invariants have their own named subtests, so an adapter
cannot quietly skip one.

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
