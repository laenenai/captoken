// Package chain is captoken's envelope: a chain of JWTs, each signed by a
// key its parent bound, which a holder can narrow offline without the
// issuer and which any JWT library can parse and signature-check.
//
// It replaces cas/internal/token's envelope.go and codec.go outright. The
// decision and its reasoning are in CHARTER.md; the wire format it
// implements is published in docs/wire-format.md and pinned by
// testdata/vectors.json.
//
// # The central invariant
//
//	No sequence of derivations can produce a token permitting more than its
//	ancestor.
//
// It is enforced twice, deliberately. Verification REFUSES any link that
// does not narrow its parent in every dimension this module orders, and it
// also computes the chain's effective authority as the INTERSECTION of
// every link, so a widening link that somehow got signed is both rejected
// and powerless. The adversarial suite in subsumption_test.go attacks every
// dimension at every link, and a mutation test removes each guard in turn
// to prove the suite is catching what it claims to.
//
// # Why there is no seal, and no proof
//
// cas needed both. A bearer holding an attenuated token held every
// ancestor's bytes, so nothing stopped them presenting a PREFIX of the
// chain and recovering the ancestor's wider authority; Token.Proof — a
// signature over the chain's last signature — existed to make a truncated
// prefix detectable.
//
// Here truncation is structurally powerless, for two reasons that compose:
//
//  1. Every proper prefix of a chain ends in a DELEGATION link, and a
//     delegation token authorises no operation at all. It is a licence to
//     derive, not a credential to spend.
//  2. Deriving a new terminal link from an ancestor requires the signing
//     key that ancestor bound in its cnf claim, and no private key is ever
//     part of a token's serialized form. A downstream holder never received
//     it. Only the party the ancestor was handed to can derive from the
//     ancestor, which is their own authority and not an escalation.
//
// So a prefix is refused with no extra machinery, and the key-custody
// hazard the Biscuit spike found — an unsealed Biscuit serializes the next
// signing private key, so a wire-only recipient can attenuate it — does not
// arise: a recipient of these bytes can never derive, sealed or not.
//
// # Why alg is pinned and there is no kid
//
// The algorithm-confusion family all begins with a verifier reading the
// token to decide how, or with what, to check the token. So: the only
// accepted alg is EdDSA over Ed25519, asserted against a constant; the
// protected header may contain nothing but alg and typ, so there is no kid,
// jwk, jku or x5u to follow; and the root public key comes from
// configuration, with every trusted root key tried in turn. The token never
// participates in key selection.
package chain

import (
	"errors"
	"fmt"
)

// FormatVersion is the value of every link's "ctv" claim. A verifier
// refuses a version it does not implement rather than guessing, which is
// how a format change fails closed instead of being partially understood.
//
// Changing it is changing the wire format: it requires a new committed
// vector and a new version of docs/wire-format.md, together.
const FormatVersion = 1

// MediaType is the value of every link's "typ" header parameter, per RFC
// 8725's recommendation that a JWT declare its application type so one
// application's token cannot be replayed into another's.
//
// It is an input to signed bytes. TestFormatConstantsArePinned asserts this
// literal, because a textual rename across the repository would otherwise
// change what every issued token says while every round-trip test still
// passed — which is exactly how audit's hash-chain domain tag was rewritten
// on 2026-10-23.
const MediaType = "captoken+jwt"

// Algorithm is the only JWS algorithm this module ever signs with or
// accepts. It is compared against a link's "alg" header for equality and is
// never used to select a key or a verification routine.
const Algorithm = "EdDSA"

// Presentation syntax: the links of a chain, root first, separated by "~",
// behind a short prefix that says what the string is.
//
// "~" is unreserved in RFC 3986 and is SD-JWT's separator for the same job,
// so a presentation is safe in a URL, a header and a form field with no
// escaping. The prefix guards against a string from an unrelated system
// being fed in by mistake and carries the presentation syntax's own
// version, which is separate from the claim-level FormatVersion: a change
// to how links are joined need not change what a link says.
const (
	Prefix    = "ct1"
	Separator = "~"
)

// TokenType is the partition the whole design rests on: what a token is
// FOR decides what it may carry, and that is what makes a naive-but-correct
// JWT verification sound rather than merely likely to be right.
//
// See docs/wire-format.md for the contract a third-party verifier is held
// to. In short:
//
//   - A delegation token authorises further derivation and NO operation.
//     Every interior link of a chain is one.
//   - An execution token authorises one operation and cannot be derived
//     from. It carries only conditions a verifier can evaluate from the
//     request in front of it.
//   - A redemption token authorises one operation subject to a server-side
//     reservation, and is the ONLY type that may carry a stateful caveat.
//     Its audience is the issuer's own reservation service, so a
//     third-party verifier refuses it on the "aud" claim alone — which
//     every mainstream JWT library checks correctly, unlike "crit".
type TokenType string

// The three token types.
const (
	TypeDelegation TokenType = "delegation"
	TypeExecution  TokenType = "execution"
	TypeRedemption TokenType = "redemption"
)

// valid reports whether t is one of the three types.
func (t TokenType) valid() bool {
	switch t {
	case TypeDelegation, TypeExecution, TypeRedemption:
		return true
	default:
		return false
	}
}

// terminal reports whether t authorises an operation. A terminal token
// carries no cnf claim and can never be a parent.
func (t TokenType) terminal() bool {
	return t == TypeExecution || t == TypeRedemption
}

// DefaultMaxLinks bounds how long a presented chain may be, so a hostile
// presentation cannot make a verifier perform an unbounded number of
// signature checks before any of them has succeeded. A chain this deep is
// already a design problem; the DelegationDepth caveat is how a consumer
// expresses its own, tighter bound.
const DefaultMaxLinks = 8

// MaxMaxLinks caps what a consumer may configure, for the same reason.
const MaxMaxLinks = 64

// ErrInvalidConfig is returned by NewMinter, NewDeriver and NewVerifier for
// an unusable configuration. It is a construction error, not a credential
// refusal, and wraps the specific cause.
var ErrInvalidConfig = errors.New("invalid configuration")

// ErrInvalidToken is returned whenever a presented chain is not a
// well-formed, internally consistent, correctly subsuming chain under a
// trusted root key: garbage bytes, the wrong prefix, an unknown format
// version, a broken or missing signature anywhere, a wrong algorithm, a
// broken parent link, a reordered or truncated or spliced chain, a link
// that does not narrow its parent, a stateful caveat on a token that may
// not carry one, or an unregistered caveat kind.
//
// Every one of those returns this exact sentinel with no further detail: no
// link index, no field name, no value. A verifier that explained WHICH
// check failed would hand a forger an oracle to iterate against. The one
// place a reason may be recorded is the issuer's own logs, and this module
// does not log.
//
// It is deliberately a different sentinel from caveat.ErrCaveatNotSatisfied:
// "this credential is not valid" and "this valid credential does not permit
// this request" are different answers, and a caller needs to be able to
// tell them apart without being told anything more.
var ErrInvalidToken = errors.New("invalid token")

// ErrBackend is returned when a stateful adapter (revocation or
// reservation) fails. The underlying error is deliberately not wrapped: it
// may contain a DSN, a host name or a driver message, and verification is
// an untrusted boundary.
var ErrBackend = errors.New("stateful backend unavailable")

// ErrNoRevocationBackend is returned by NewVerifier when neither
// Revocations nor the explicit NoRevocation opt-out is configured. A
// verifier that silently skipped revocation would accept a revoked chain
// forever, so the omission is a construction error rather than a default.
var ErrNoRevocationBackend = errors.New("no revocation backend")

// ErrNotAuthorizing is returned when a structurally valid chain is
// presented for an authorization decision but its terminal link authorises
// no operation — a delegation token. It wraps ErrInvalidToken, because from
// the presenter's point of view it is the same refusal, and is distinct
// only so an operator reading their own logs can tell a truncated chain
// from a forged one.
var ErrNotAuthorizing = fmt.Errorf("%w: token authorises no operation", ErrInvalidToken)
