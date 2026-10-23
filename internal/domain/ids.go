package domain

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"unicode/utf8"
)

// ErrMalformedID is returned when an identifier a token carries cannot be
// one: empty, over the length bound, or not valid UTF-8.
var ErrMalformedID = newSentinel("malformed id")

// maxIDLen bounds every identifier a token carries. The bound exists so
// that a hostile token cannot make a verifier hold an arbitrarily long
// string before any signature has been checked, and so that a token's size
// is predictable for the ~2,000 character practical URL budget. It is
// generous for an opaque id and far below anything that costs memory.
const maxIDLen = 255

// Subject is the opaque identifier of whoever a token was minted for. The
// charter is explicit that this module knows nothing about principals: a
// subject is a string it carries, compares for equality, and never
// interprets or resolves.
type Subject string

// Issuer is the opaque identifier of whoever minted a chain's root.
type Issuer string

// Audience is one opaque identifier of a party a token is intended for. It
// is the standard "aud" claim, and the reason it is load-bearing here is
// recorded in docs/wire-format.md: a redemption token's audience names the
// issuer's own reservation service, so a third-party verifier that checks
// "aud" — as RFC 7519 requires and as every mainstream library actually
// does — refuses a stateful token without needing to know that stateful
// caveats exist.
type Audience string

// TokenID identifies one link of one chain, uniquely and for good. It is
// the standard "jti" claim.
type TokenID string

// ChainID identifies a whole chain: by construction it is the root link's
// TokenID, which is why it is byte-identical in every descendant and why
// revoking it revokes the chain. See RevocationID.
type ChainID string

// ParseID validates s as an identifier this module will carry in signed
// bytes. what names the field for the error's text; it is a fixed literal
// at every call site, never a value from a token or a request.
func ParseID(what, s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrMalformedID, what)
	}
	if len(s) > maxIDLen {
		return "", fmt.Errorf("%w: %s is too long", ErrMalformedID, what)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: %s is not valid UTF-8", ErrMalformedID, what)
	}
	return s, nil
}

// NewTokenID returns a fresh, unguessable TokenID: 128 bits of entropy,
// base64url without padding.
//
// Unguessability is a requirement rather than a nicety. A chain's root
// TokenID is also its ChainID and therefore its revocation identifier, so
// a predictable one would let anyone who can enumerate ids revoke other
// people's chains through whatever interface accepts a revocation.
func NewTokenID() (TokenID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand's error names only an entropy-source failure and
		// carries no caller input, so wrapping it leaks nothing.
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return TokenID(base64.RawURLEncoding.EncodeToString(b[:])), nil
}

// RevocationID is the identifier a revocation record is keyed on. A chain
// has exactly one, and it is the chain's ChainID — the root link's TokenID.
//
// Deriving it from the ancestor rather than from the presented token is the
// property the Biscuit spike found Biscuit getting for free and recommended
// this design should too: the id is byte-identical in every descendant, so
// revoking a parent revokes every token ever derived from it, with no
// enumeration of descendants and no walk of a revocation tree. cas's
// Fingerprint had no equivalent — it hashed the whole token, so revoking a
// parent left its children alive.
//
// It is also immune to the canonicalization hazard Fingerprint's doc
// comment describes. A revocation or single-use record keyed on the
// presented string can be defeated by a byte-level permutation that still
// verifies; the ChainID is a claim inside the signed bytes, so there is
// nothing to re-encode and no canonical form to agree on.
type RevocationID = ChainID
