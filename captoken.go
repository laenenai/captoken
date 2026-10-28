// Package captoken is the public facade for the captoken module: a bearer
// credential that can only ever be narrowed.
//
// What it does, per CHARTER.md: minting, attenuation, typed caveats,
// offline verification, chain revocation and single-use nonces. What it
// does not contain is any knowledge of principals, groups or policy —
// subjects are opaque ids, permissions are opaque labels, and a consumer's
// resource hierarchy is data it declares rather than behaviour this module
// knows. It cannot answer "may they?"; only "is this credential valid, and
// what does it permit?"
//
// # The central invariant
//
//	No sequence of derivations can produce a token permitting more than its
//	ancestor.
//
// Verification enforces it twice: it refuses any link that does not narrow
// its parent in every dimension this module orders, and it computes the
// chain's authority as the intersection of every link, so a widening link
// that somehow got signed is both rejected and powerless. The adversarial
// suite in chain attacks every dimension at every link, and a mutation test
// removes each guard in turn to prove the suite catches what it claims to.
//
// # Shape
//
// Every value object lives in domain, the caveat vocabulary in caveat, the
// envelope in chain and the stateful subset's ports in reserve. This file
// re-exports what a consumer must name, as type ALIASES, so a value the
// authoritative packages produce and a value a consumer holds are the
// identical type rather than a copy needing conversion at the boundary.
//
// It carries aliases, sentinel errors, exported constants and the module's
// entry points — and no logic. Every function here is a one-line forward.
// A facade that hides what the module is for is not a facade.
//
// # Where to start
//
//   - docs/wire-format.md is the published format, and the authority on
//     what a token says. It is pinned by chain/testdata/vectors.json.
//   - captokentest.RunCapabilitySuite, not these interfaces, is the
//     authoritative description of the contract's edge-case behaviour. A
//     consumer counts as having adopted this module when that suite runs
//     green in its own CI against its own wiring.
package captoken

import (
	"crypto/ed25519"
	"io"
	"time"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/chain"
	"github.com/laenenai/captoken/domain"
	"github.com/laenenai/captoken/reserve"
)

// Value objects: a consumer's resource model, its permission labels, and
// the opaque identifiers a token carries.
type (
	// ResourceSchema is the consumer's declared resource hierarchy — the
	// one thing this module knows about a consumer's resource model, and
	// deliberately the only thing. See domain.ResourceSchema for why it is
	// declared data rather than an interface a consumer implements.
	ResourceSchema = domain.ResourceSchema
	// SegmentKind declares one level of that hierarchy.
	SegmentKind = domain.SegmentKind
	// Segment is one (kind, id) step of a path.
	Segment = domain.Segment
	// ResourcePath is one validated node of the hierarchy. It is opaque:
	// the only way to obtain one is through a ResourceSchema, which is
	// what makes a path that never passed its schema impossible rather
	// than merely discouraged.
	ResourcePath = domain.ResourcePath

	// Permission is one opaque capability label. This module compares them
	// for equality and computes set containment; what they mean is the
	// consumer's business.
	Permission = domain.Permission
	// PermissionSet is a set of permission labels.
	PermissionSet = domain.PermissionSet

	// Subject is who a token was minted for, opaque.
	Subject = domain.Subject
	// Issuer is who minted a chain's root, opaque.
	Issuer = domain.Issuer
	// Audience is one party a token is intended for. It is load-bearing:
	// see TypeRedemption.
	Audience = domain.Audience
	// TokenID identifies one link of one chain.
	TokenID = domain.TokenID
	// ChainID identifies a whole chain, and is its revocation key.
	ChainID = domain.ChainID
	// RevocationID is the identifier a revocation record is keyed on —
	// the chain's root token id, byte-identical in every descendant.
	RevocationID = domain.RevocationID

	// Clock abstracts the current time.
	Clock = domain.Clock
	// SystemClock is the production Clock.
	SystemClock = domain.SystemClock
	// FixedClock is a test Clock.
	FixedClock = domain.FixedClock
)

// The caveat vocabulary: sixteen typed narrowing conditions, and the
// request facts they are checked against.
type (
	// Caveat is a narrowing condition carried by one link of a chain.
	Caveat = caveat.Caveat
	// Request carries the concrete facts of one access attempt.
	Request = caveat.Request
	// Grant is one link's complete narrowing content.
	Grant = caveat.Grant

	// ExpiresAt refuses a request after an instant. Carried as the "exp"
	// claim.
	ExpiresAt = caveat.ExpiresAt
	// NotBefore refuses a request before an instant. Carried as "nbf".
	NotBefore = caveat.NotBefore
	// ResourceScope refuses a request outside its scopes. Carried as
	// "res".
	ResourceScope = caveat.ResourceScope
	// PermissionSetCaveat refuses a request for a permission outside its
	// set. Carried as "prm".
	//
	// It is named differently from the PermissionSet value type because Go
	// has one name space for both and they are different things: one is a
	// set of labels, the other is a condition over a request.
	PermissionSetCaveat = caveat.PermissionSet
	// MaxContentLength refuses an upload larger than its bound. An unknown
	// length fails closed.
	MaxContentLength = caveat.MaxContentLength
	// AllowedContentTypes refuses an upload whose SNIFFED content type is
	// not exactly one of its entries.
	AllowedContentTypes = caveat.AllowedContentTypes
	// RequireAuthenticatedRecipient refuses an anonymous bearer.
	RequireAuthenticatedRecipient = caveat.RequireAuthenticatedRecipient
	// RequiredReadiness refuses a target whose readiness is not listed.
	RequiredReadiness = caveat.RequiredReadiness
	// RequireDeclaredDigest refuses an upload that declared no content
	// address.
	RequireDeclaredDigest = caveat.RequireDeclaredDigest
	// ClientCIDR refuses a client address outside its prefix.
	ClientCIDR = caveat.ClientCIDR
	// DelegationDepth bounds the total number of links in a chain.
	DelegationDepth = caveat.DelegationDepth
	// ProcessorAudience refuses a processor whose identity does not match.
	ProcessorAudience = caveat.ProcessorAudience
	// Watermark restricts a token to one named rendition.
	Watermark = caveat.Watermark

	// MaxUses refuses a request once the chain has been redeemed that many
	// times. STATEFUL: it may appear only on a redemption token.
	MaxUses = caveat.MaxUses
	// ExpiresAfterFirstUse refuses a request once a window has elapsed
	// since the chain's first redemption. STATEFUL.
	ExpiresAfterFirstUse = caveat.ExpiresAfterFirstUse
	// MaxBytesTransferred bounds the cumulative bytes served under a
	// chain. STATEFUL.
	MaxBytesTransferred = caveat.MaxBytesTransferred
)

// The envelope: minting, offline derivation and verification.
type (
	// TokenType is the partition the whole design rests on. See
	// TypeDelegation, TypeExecution and TypeRedemption.
	TokenType = chain.TokenType
	// MintSpec describes the token to mint or derive.
	MintSpec = chain.MintSpec
	// Minted is a freshly minted or derived token, with the private key
	// its holder needs in order to derive from it — returned beside the
	// token, never inside it.
	Minted = chain.Minted
	// KeyPair is an Ed25519 keypair.
	KeyPair = chain.KeyPair

	// Minter mints root tokens.
	Minter = chain.Minter
	// MinterConfig configures NewMinter.
	MinterConfig = chain.MinterConfig
	// Deriver appends a narrower link to a chain, offline, with no call to
	// the issuer.
	Deriver = chain.Deriver
	// DeriverConfig configures NewDeriver.
	DeriverConfig = chain.DeriverConfig
	// Verifier verifies presented chains.
	Verifier = chain.Verifier
	// VerifierConfig configures NewVerifier.
	VerifierConfig = chain.VerifierConfig
	// Verified is what a successful verification establishes.
	Verified = chain.Verified
)

// The stateful subset's ports, and the in-memory adapter for them.
type (
	// Reservation is the counter snapshot one authorization is evaluated
	// against.
	Reservation = reserve.Reservation
	// Advance is the amount to add to a chain's counters once the
	// operation they guarded has SUCCEEDED.
	Advance = reserve.Advance
	// Counters reads and advances the per-chain counters the stateful
	// caveats check against. Read never advances; see reserve's package
	// doc for the ordering a caller owns.
	Counters = reserve.Counters
	// Revocations answers whether a chain has been revoked.
	Revocations = reserve.Revocations
	// Nonces records single-use nonces.
	Nonces = reserve.Nonces
	// Memory is an in-memory Counters, Revocations and Nonces, for tests.
	Memory = reserve.Memory
	// Stub is the placeholder for the remote reservation service's
	// transport, which this increment does not build. Every method
	// refuses, so the fail-closed path has a name and a test.
	Stub = reserve.Stub
)

// The three token types. See docs/wire-format.md for the table of what
// each may carry.
const (
	// TypeDelegation authorises further derivation and NO operation. Every
	// interior link of a chain is one, which is what makes a truncated
	// chain powerless.
	TypeDelegation = chain.TypeDelegation
	// TypeExecution authorises one operation and cannot be derived from.
	TypeExecution = chain.TypeExecution
	// TypeRedemption authorises one operation subject to a server-side
	// reservation, and is the only type that may carry a stateful caveat.
	// Its audience is the issuer's own reservation service, so a
	// third-party verifier refuses it on the "aud" claim alone.
	TypeRedemption = chain.TypeRedemption
)

// Format constants. Each is an input to signed bytes and is pinned as a
// literal by a test; changing one is a wire-format change that needs a new
// FormatVersion and a new committed vector, together.
const (
	// FormatVersion is the value of every link's "ctv" claim.
	FormatVersion = chain.FormatVersion
	// MediaType is the value of every link's "typ" header parameter.
	MediaType = chain.MediaType
	// Algorithm is the only JWS algorithm this module signs with or
	// accepts. It is compared against a constant and never read from a
	// token to select a key.
	Algorithm = chain.Algorithm
	// Prefix and Separator are the presentation syntax: Prefix, then each
	// link root-first, joined by Separator.
	Prefix    = chain.Prefix
	Separator = chain.Separator
	// DefaultMaxLinks and MaxMaxLinks bound a presented chain's length.
	DefaultMaxLinks = chain.DefaultMaxLinks
	MaxMaxLinks     = chain.MaxMaxLinks
	// MaxPresentationBytes bounds the whole presentation before parsing.
	MaxPresentationBytes = chain.MaxPresentationBytes
	// MaxListEntries bounds every list in a signed claim.
	MaxListEntries = chain.MaxListEntries
	// MaxIDLength bounds every identifier, permission and resource segment.
	MaxIDLength = domain.MaxIDLength
)

// Sentinel errors. Every one of them is a bare cause: a refusal names
// nothing — not the check that failed, not a claim, not a value — because
// a verifier that explains why a request was refused hands an attacker a
// dimension to search along.
var (
	// ErrInvalidToken means the credential is not well formed, not
	// correctly signed, not correctly linked, or widens an ancestor.
	ErrInvalidToken = chain.ErrInvalidToken
	// ErrNotAuthorizing means the presented chain's terminal link
	// authorises no operation — a delegation token, which is what every
	// truncated chain ends in. It wraps ErrInvalidToken and is the one
	// preserved distinction, because it reveals only something the
	// presenter already knows.
	ErrNotAuthorizing = chain.ErrNotAuthorizing

	// ErrCaveatNotSatisfied means the credential is valid and does not
	// permit this request.
	ErrCaveatNotSatisfied = caveat.ErrCaveatNotSatisfied
	// ErrUnknownCaveat means a caveat kind is not one this build
	// recognizes, or a caveat value is nil. A verifier that ignored what
	// it did not understand would be a bypass.
	ErrUnknownCaveat = caveat.ErrUnknownCaveat
	// ErrEmptyChain means a chain of zero links was checked, which
	// authorises nothing.
	ErrEmptyChain = caveat.ErrEmptyChain

	// ErrMalformedResourceSchema means a declared hierarchy is not usable.
	ErrMalformedResourceSchema = domain.ErrMalformedResourceSchema
	// ErrMalformedResourcePath means segments do not form a path the
	// hierarchy allows.
	ErrMalformedResourcePath = domain.ErrMalformedResourcePath
	// ErrUnresolvedResourcePath means a path was never constructed through
	// a schema. A caller must treat it as a reason to refuse, never as
	// "this path contains nothing".
	ErrUnresolvedResourcePath = domain.ErrUnresolvedResourcePath
	// ErrMalformedPermission means a label cannot be a permission.
	ErrMalformedPermission = domain.ErrMalformedPermission
	// ErrMalformedID means an identifier cannot be one.
	ErrMalformedID = domain.ErrMalformedID

	// ErrInvalidConfig means a constructor received an unusable
	// configuration. It is distinct from ErrInvalidToken, which is about a
	// presented credential.
	ErrInvalidConfig = chain.ErrInvalidConfig
	// ErrBackend means a revocation or reservation adapter failed. Its
	// underlying error is not exposed because it may contain deployment
	// details.
	ErrBackend = chain.ErrBackend
	// ErrNoRevocationBackend means a verifier was constructed without
	// Revocations and without the explicit NoRevocation opt-out. It is a
	// construction error, not a credential refusal.
	ErrNoRevocationBackend = chain.ErrNoRevocationBackend
	// ErrNoReservationService means a redemption token was presented to a
	// verifier with no Counters wired up. It is the fail-closed outcome
	// the charter's two-surface design rests on.
	ErrNoReservationService = reserve.ErrNoReservationService
	// ErrRevoked means the chain's revocation identifier is recorded as
	// revoked.
	ErrRevoked = reserve.ErrRevoked
	// ErrNonceConsumed means a single-use nonce has already been recorded.
	ErrNonceConsumed = reserve.ErrNonceConsumed
)

// NewResourceSchema declares a consumer's resource hierarchy, outermost
// level first.
func NewResourceSchema(kinds ...SegmentKind) (ResourceSchema, error) {
	return domain.NewResourceSchema(kinds...)
}

// ParsePermission validates s as a permission label.
func ParsePermission(s string) (Permission, error) { return domain.ParsePermission(s) }

// NewPermissionSet returns the set containing perms.
func NewPermissionSet(perms ...Permission) PermissionSet { return domain.NewPermissionSet(perms...) }

// NewTokenID returns a fresh, unguessable token identifier.
func NewTokenID() (TokenID, error) { return domain.NewTokenID() }

// NewFixedClock returns a test Clock starting at t.
func NewFixedClock(t time.Time) *FixedClock { return domain.NewFixedClock(t) }

// CanonicalTime normalizes t to UTC at microsecond precision. Everything
// that compares or stores an instant goes through it.
func CanonicalTime(t time.Time) time.Time { return domain.CanonicalTime(t) }

// JWTNotAfter normalizes an expiry for a NumericDate claim, flooring it to
// a whole second so the bound moves inwards. See JWTNotBefore for why the
// direction matters.
func JWTNotAfter(t time.Time) time.Time { return domain.JWTNotAfter(t) }

// JWTNotBefore normalizes a start instant for a NumericDate claim, ceiling
// it to a whole second. The asymmetry with JWTNotAfter is deliberate:
// NumericDate is whole seconds, so flooring both would push a start earlier
// and widen the validity window, and a widening that is "only a second" is
// still a widening the central invariant forbids.
func JWTNotBefore(t time.Time) time.Time { return domain.JWTNotBefore(t) }

// GenerateKey returns a fresh Ed25519 keypair, reading entropy from rand. A
// nil rand reads crypto/rand.Reader.
func GenerateKey(rand io.Reader) (KeyPair, error) { return chain.GenerateKey(rand) }

// PublicKeyThumbprint names an Ed25519 public key by its RFC 7638 JWK
// thumbprint, for an operator's own key inventory.
func PublicKeyThumbprint(pub ed25519.PublicKey) (string, error) {
	return chain.PublicKeyThumbprint(pub)
}

// NewMinter validates cfg and returns a Minter, which mints root tokens.
func NewMinter(cfg MinterConfig) (*Minter, error) { return chain.NewMinter(cfg) }

// NewDeriver validates cfg and returns a Deriver, which appends a narrower
// link to a chain offline.
func NewDeriver(cfg DeriverConfig) (*Deriver, error) { return chain.NewDeriver(cfg) }

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) { return chain.NewVerifier(cfg) }

// NewMemory returns an empty in-memory Counters, Revocations and Nonces.
// It is for tests: its state is per-process, and the ordering discipline
// the counters require needs a real transaction.
func NewMemory() *Memory { return reserve.NewMemory() }

// CheckAll checks req against every grant in a chain — the intersection,
// all of which must pass. Verification calls it; it is exported so a
// consumer can evaluate an in-memory chain, and it gives such a chain the
// same fail-closed guarantees: an empty chain, a nil caveat and an
// unrecognized caveat kind are all refused.
func CheckAll(chainGrants []Grant, req Request) error {
	return caveat.CheckAll(chainGrants, req)
}

// IsStatefulKind reports whether a caveat kind requires a server-side
// reservation, and may therefore appear only on a redemption token.
func IsStatefulKind(kind string) bool { return caveat.IsStatefulKind(kind) }

// StatefulKinds returns the stateful caveat kinds, sorted.
func StatefulKinds() []string { return caveat.StatefulKinds() }

// HasStandardClaim reports whether a caveat kind is carried as a standard
// JWT claim — exp, nbf, prm or res — rather than as an entry in a token's
// "cav" array. Such a kind is set through MintSpec's own fields, and a
// token carrying one in "cav" is refused: see docs/wire-format.md.
func HasStandardClaim(kind string) bool { return caveat.HasStandardClaim(kind) }

// StandardClaimKinds returns the caveat kinds carried as standard claims,
// sorted.
func StandardClaimKinds() []string { return caveat.StandardClaimKinds() }

// RegisteredKinds returns every caveat kind this build understands,
// sorted. The vocabulary is closed — see docs/wire-format.md — so this is
// what a consumer reports, not what it extends.
func RegisteredKinds() []string { return caveat.RegisteredKinds() }
