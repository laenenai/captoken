package caveat

// This file implements every concrete Caveat in captoken's vocabulary. Each
// follows the same shape: a Go type wrapping the value it carries,
// Kind/Check/Narrows satisfying Caveat, encodeValue satisfying
// encodableCaveat, a decoder, and an init registering it.
//
// clockSkewTolerance (60s, applied symmetrically) governs every time-based
// check: ExpiresAt, NotBefore and ExpiresAfterFirstUse all tolerate that
// much clock disagreement between whichever clock set the bound and
// whichever clock produced Request.Now.
//
// Every wire value here is canonical: any list whose order carries no
// meaning is sorted on the way out, so the same caveat always produces the
// same signed bytes. See docs/wire-format.md for the shape of each.

import (
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/laenenai/captoken/domain"
)

// The registered kind of every caveat. These strings are part of the
// published wire format: they appear verbatim in a token's "cav" claim, and
// TestCaveatKindsArePinned asserts each literal, because a textual rename
// across the repository would otherwise silently change what every issued
// token says.
const (
	kindExpiresAt                     = "expires_at"
	kindNotBefore                     = "not_before"
	kindExpiresAfterFirstUse          = "expires_after_first_use"
	kindMaxUses                       = "max_uses"
	kindResourceScope                 = "resource_scope"
	kindPermissionSet                 = "permission_set"
	kindMaxContentLength              = "max_content_length"
	kindAllowedContentTypes           = "allowed_content_types"
	kindMaxBytesTransferred           = "max_bytes_transferred"
	kindRequireAuthenticatedRecipient = "require_authenticated_recipient"
	kindRequiredReadiness             = "required_readiness"
	kindRequireDeclaredDigest         = "require_declared_digest"
	kindClientCIDR                    = "client_cidr"
	kindDelegationDepth               = "delegation_depth"
	kindProcessorAudience             = "processor_audience"
	kindWatermark                     = "watermark"
)

// ---- ExpiresAt ------------------------------------------------------------

// ExpiresAt refuses a request after this instant, tolerant of
// clockSkewTolerance. Its wire form is the standard "exp" claim rather than
// an entry in the caveat array — see Grant.
type ExpiresAt time.Time

// Kind implements Caveat.
func (e ExpiresAt) Kind() string { return kindExpiresAt }

// Check implements Caveat.
func (e ExpiresAt) Check(req Request) error {
	if req.Now.After(time.Time(e).Add(clockSkewTolerance)) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether e expires at or before parent — a child can only
// bring expiry earlier, never later.
func (e ExpiresAt) Narrows(parent Caveat) bool {
	p, ok := parent.(ExpiresAt)
	if !ok {
		return false
	}
	return !time.Time(e).After(time.Time(p))
}

func (e ExpiresAt) encodeValue() (any, error) {
	return domain.JWTNotAfter(time.Time(e)).Unix(), nil
}

func decodeExpiresAt(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	secs, err := decodeUnixSeconds(value)
	if err != nil {
		return nil, err
	}
	return ExpiresAt(time.Unix(secs, 0).UTC()), nil
}

func init() { registerCaveat(kindExpiresAt, decodeExpiresAt) }

// ---- NotBefore ------------------------------------------------------------

// NotBefore refuses a request before this instant, tolerant of
// clockSkewTolerance. Its wire form is the standard "nbf" claim.
type NotBefore time.Time

// Kind implements Caveat.
func (n NotBefore) Kind() string { return kindNotBefore }

// Check implements Caveat.
func (n NotBefore) Check(req Request) error {
	if req.Now.Before(time.Time(n).Add(-clockSkewTolerance)) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether n starts at or after parent — a child can only
// push the start later, never earlier.
func (n NotBefore) Narrows(parent Caveat) bool {
	p, ok := parent.(NotBefore)
	if !ok {
		return false
	}
	return !time.Time(n).Before(time.Time(p))
}

func (n NotBefore) encodeValue() (any, error) {
	return domain.JWTNotBefore(time.Time(n)).Unix(), nil
}

func decodeNotBefore(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	secs, err := decodeUnixSeconds(value)
	if err != nil {
		return nil, err
	}
	return NotBefore(time.Unix(secs, 0).UTC()), nil
}

func init() { registerCaveat(kindNotBefore, decodeNotBefore) }

// ---- ExpiresAfterFirstUse -------------------------------------------------

// ExpiresAfterFirstUse refuses a request once this duration has elapsed
// since the chain's first redemption (Request.FirstUsedAt), not since
// issuance. A zero Request.FirstUsedAt means this would be the first use,
// which always passes — the caller records the first-use instant
// transactionally once that request succeeds.
//
// It is STATEFUL: FirstUsedAt is a counter only the issuer holds, so this
// caveat may appear only on a redemption token.
type ExpiresAfterFirstUse time.Duration

// Kind implements Caveat.
func (e ExpiresAfterFirstUse) Kind() string { return kindExpiresAfterFirstUse }

// Check implements Caveat.
func (e ExpiresAfterFirstUse) Check(req Request) error {
	if req.FirstUsedAt.IsZero() {
		return nil
	}
	deadline := req.FirstUsedAt.Add(time.Duration(e)).Add(clockSkewTolerance)
	if req.Now.After(deadline) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether e's window is no longer than parent's.
func (e ExpiresAfterFirstUse) Narrows(parent Caveat) bool {
	p, ok := parent.(ExpiresAfterFirstUse)
	if !ok {
		return false
	}
	return e <= p
}

func (e ExpiresAfterFirstUse) encodeValue() (any, error) {
	return int64(time.Duration(e) / time.Second), nil
}

func decodeExpiresAfterFirstUse(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	n, err := decodeNonNegativeInt(value)
	if err != nil {
		return nil, err
	}
	// Multiplying by time.Second must not wrap. The allowed range is still
	// about 292 years, far beyond any legitimate first-use window.
	if n > int64(math.MaxInt64)/int64(time.Second) {
		return nil, errMalformedValue
	}
	return ExpiresAfterFirstUse(time.Duration(n) * time.Second), nil
}

func init() { registerCaveat(kindExpiresAfterFirstUse, decodeExpiresAfterFirstUse) }

// ---- MaxUses --------------------------------------------------------------

// MaxUses refuses a request once the chain has already been redeemed this
// many times. MaxUses(1) is the single-use token: there is no separate
// single-use kind. Request.UsesBefore is a snapshot the caller reads inside
// its redemption transaction; the caller, not this type, makes the
// read-check-increment atomic under concurrent redemption.
//
// It is STATEFUL, and therefore redemption-only.
type MaxUses int64

// Kind implements Caveat.
func (m MaxUses) Kind() string { return kindMaxUses }

// Check implements Caveat.
func (m MaxUses) Check(req Request) error {
	if req.UsesBefore < 0 || int64(req.UsesBefore) >= int64(m) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether m allows no more uses than parent.
func (m MaxUses) Narrows(parent Caveat) bool {
	p, ok := parent.(MaxUses)
	if !ok {
		return false
	}
	return m <= p
}

func (m MaxUses) encodeValue() (any, error) { return int64(m), nil }

func decodeMaxUses(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	n, err := decodeNonNegativeInt(value)
	if err != nil {
		return nil, err
	}
	return MaxUses(n), nil
}

func init() { registerCaveat(kindMaxUses, decodeMaxUses) }

// ---- ResourceScope --------------------------------------------------------

// ResourceScope refuses a request for any resource none of its scopes
// contains. Containment is domain.ResourcePath's: a document scope also
// covers its slots and their elements, a fileset scope covers everything
// nested beneath it, and a sibling whose id merely shares a prefix is never
// covered.
//
// The scopes are a union: a request in any one of them passes. Two
// ResourceScope caveats on the same chain intersect, because CheckAll
// requires every caveat to pass. That merges cas's Block.Resources list
// and its single-scope ResourceScope caveat, which were the same dimension
// expressed twice.
//
// Its wire form is the standard "res" claim rather than an entry in the
// caveat array — see Grant.
type ResourceScope struct{ Scopes []domain.ResourcePath }

// Kind implements Caveat.
func (s ResourceScope) Kind() string { return kindResourceScope }

// Check implements Caveat. A request whose resource cannot be evaluated at
// all (domain.ErrUnresolvedResourcePath) is treated the same as one outside
// every scope — fail closed, never "no path, so no restriction applies".
func (s ResourceScope) Check(req Request) error {
	for _, scope := range s.Scopes {
		contains, err := scope.Contains(req.Resource)
		if err == nil && contains {
			return nil
		}
	}
	return ErrCaveatNotSatisfied
}

// Narrows reports whether every scope in s is contained by some scope in
// parent — s may only shrink the resource scope, never point outside it. A
// containment that cannot be proven does not narrow: mint time must refuse
// what it cannot verify, not assume it is safe. An empty s narrows nothing
// into nothing, which is vacuously narrower.
func (s ResourceScope) Narrows(parent Caveat) bool {
	p, ok := parent.(ResourceScope)
	if !ok {
		return false
	}
	for _, child := range s.Scopes {
		contained := false
		for _, outer := range p.Scopes {
			if ok, err := outer.Contains(child); err == nil && ok {
				contained = true
				break
			}
		}
		if !contained {
			return false
		}
	}
	return true
}

func (s ResourceScope) encodeValue() (any, error) {
	return EncodePaths(s.Scopes)
}

func decodeResourceScope(value []byte, schema domain.ResourceSchema) (Caveat, error) {
	var wire [][][]string
	if err := json.Unmarshal(value, &wire); err != nil {
		return nil, errMalformedValue
	}
	paths, err := DecodePaths(wire, schema)
	if err != nil {
		return nil, err
	}
	return ResourceScope{Scopes: paths}, nil
}

func init() { registerCaveat(kindResourceScope, decodeResourceScope) }

// ---- PermissionSet --------------------------------------------------------

// PermissionSet refuses a request whose Permission is not in the set. Its
// wire form is the standard "prm" claim rather than an entry in the caveat
// array — see Grant.
type PermissionSet domain.PermissionSet

// Kind implements Caveat.
func (s PermissionSet) Kind() string { return kindPermissionSet }

// Check implements Caveat.
func (s PermissionSet) Check(req Request) error {
	if !domain.PermissionSet(s).Contains(req.Permission) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether s is a subset of parent's permissions.
func (s PermissionSet) Narrows(parent Caveat) bool {
	p, ok := parent.(PermissionSet)
	if !ok {
		return false
	}
	return domain.PermissionSet(s).IsSubsetOf(domain.PermissionSet(p))
}

func (s PermissionSet) encodeValue() (any, error) {
	sorted := domain.PermissionSet(s).Sorted()
	out := make([]string, len(sorted))
	for i, p := range sorted {
		out[i] = string(p)
	}
	return out, nil
}

func decodePermissionSet(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	var wire []string
	if err := json.Unmarshal(value, &wire); err != nil {
		return nil, errMalformedValue
	}
	perms := make([]domain.Permission, len(wire))
	for i, s := range wire {
		p, err := domain.ParsePermission(s)
		if err != nil {
			return nil, errMalformedValue
		}
		perms[i] = p
	}
	return PermissionSet(domain.NewPermissionSet(perms...)), nil
}

func init() { registerCaveat(kindPermissionSet, decodePermissionSet) }

// ---- MaxContentLength -----------------------------------------------------

// MaxContentLength refuses an upload larger than this many bytes.
// Request.ContentLength == -1 (an unknown, e.g. chunked, length) fails
// closed: a caveat that cannot verify a bound does not grant it by default.
type MaxContentLength int64

// Kind implements Caveat.
func (m MaxContentLength) Kind() string { return kindMaxContentLength }

// Check implements Caveat.
func (m MaxContentLength) Check(req Request) error {
	if req.ContentLength < 0 || req.ContentLength > int64(m) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether m allows no more bytes than parent.
func (m MaxContentLength) Narrows(parent Caveat) bool {
	p, ok := parent.(MaxContentLength)
	if !ok {
		return false
	}
	return m <= p
}

func (m MaxContentLength) encodeValue() (any, error) { return int64(m), nil }

func decodeMaxContentLength(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	n, err := decodeNonNegativeInt(value)
	if err != nil {
		return nil, err
	}
	return MaxContentLength(n), nil
}

func init() { registerCaveat(kindMaxContentLength, decodeMaxContentLength) }

// ---- AllowedContentTypes --------------------------------------------------

// AllowedContentTypes refuses an upload whose Request.ContentType is not
// exactly one of these strings.
//
// Request.ContentType is contractually the SNIFFED type of the bytes on the
// wire, never a caller-declared header. This caveat does no MIME parameter
// parsing of its own and compares the whole string verbatim, which is
// deliberate: a sniffer never produces parameters, so
// "application/pdf; charset=../../x" — smuggled parameters tacked onto a
// declared header a careless caller passed through instead of sniffing —
// fails this exact-match check exactly as it should, with no special-case
// logic required to catch it.
type AllowedContentTypes []string

// Kind implements Caveat.
func (a AllowedContentTypes) Kind() string { return kindAllowedContentTypes }

// Check implements Caveat.
func (a AllowedContentTypes) Check(req Request) error {
	if slices.Contains(a, req.ContentType) {
		return nil
	}
	return ErrCaveatNotSatisfied
}

// Narrows reports whether every type a allows, parent also allows.
func (a AllowedContentTypes) Narrows(parent Caveat) bool {
	p, ok := parent.(AllowedContentTypes)
	if !ok {
		return false
	}
	for _, t := range a {
		if !slices.Contains(p, t) {
			return false
		}
	}
	return true
}

func (a AllowedContentTypes) encodeValue() (any, error) {
	return sortedUnique(a), nil
}

func decodeAllowedContentTypes(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	wire, err := decodeNonEmptyStrings(value)
	if err != nil {
		return nil, err
	}
	return AllowedContentTypes(wire), nil
}

func init() { registerCaveat(kindAllowedContentTypes, decodeAllowedContentTypes) }

// ---- MaxBytesTransferred --------------------------------------------------

// MaxBytesTransferred refuses a request once the bytes already served under
// this chain (Request.BytesTransferredBefore) plus this request's
// ContentLength would exceed the limit. Request.ContentLength == -1 fails
// closed, for the same reason as MaxContentLength.
//
// It is STATEFUL, and therefore redemption-only.
type MaxBytesTransferred int64

// Kind implements Caveat.
func (m MaxBytesTransferred) Kind() string { return kindMaxBytesTransferred }

// Check implements Caveat.
func (m MaxBytesTransferred) Check(req Request) error {
	// ContentLength is attacker-declared on an upload (net/http parses an
	// arbitrarily large Content-Length header without complaint), so
	// req.BytesTransferredBefore+req.ContentLength can overflow int64 and
	// wrap negative, passing a comparison against the limit that would
	// otherwise have caught it. Rearranging to req.ContentLength >
	// int64(m)-req.BytesTransferredBefore never adds two attacker-reachable
	// values together, so it cannot overflow.
	if req.ContentLength < 0 || req.BytesTransferredBefore < 0 {
		return ErrCaveatNotSatisfied
	}
	if req.ContentLength > int64(m)-req.BytesTransferredBefore {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether m allows no more cumulative bytes than parent.
func (m MaxBytesTransferred) Narrows(parent Caveat) bool {
	p, ok := parent.(MaxBytesTransferred)
	if !ok {
		return false
	}
	return m <= p
}

func (m MaxBytesTransferred) encodeValue() (any, error) { return int64(m), nil }

func decodeMaxBytesTransferred(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	n, err := decodeNonNegativeInt(value)
	if err != nil {
		return nil, err
	}
	return MaxBytesTransferred(n), nil
}

func init() { registerCaveat(kindMaxBytesTransferred, decodeMaxBytesTransferred) }

// ---- RequireAuthenticatedRecipient ----------------------------------------

// RequireAuthenticatedRecipient refuses a request from an anonymous bearer:
// Request.AuthenticatedRecipient must be true.
type RequireAuthenticatedRecipient struct{}

// Kind implements Caveat.
func (RequireAuthenticatedRecipient) Kind() string { return kindRequireAuthenticatedRecipient }

// Check implements Caveat.
func (RequireAuthenticatedRecipient) Check(req Request) error {
	if !req.AuthenticatedRecipient {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether parent carries the same requirement: a presence
// flag cannot be made more or less restrictive, only kept.
func (RequireAuthenticatedRecipient) Narrows(parent Caveat) bool {
	_, ok := parent.(RequireAuthenticatedRecipient)
	return ok
}

func (RequireAuthenticatedRecipient) encodeValue() (any, error) { return true, nil }

func decodeRequireAuthenticatedRecipient(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	if err := decodePresenceFlag(value); err != nil {
		return nil, err
	}
	return RequireAuthenticatedRecipient{}, nil
}

func init() { registerCaveat(kindRequireAuthenticatedRecipient, decodeRequireAuthenticatedRecipient) }

// ---- RequiredReadiness ----------------------------------------------------

// RequiredReadiness refuses a request unless the target's current
// Request.Readiness is one of these states. An empty Request.Readiness —
// "nobody populated this" — satisfies no state, which is the fail-closed
// direction.
type RequiredReadiness []string

// Kind implements Caveat.
func (r RequiredReadiness) Kind() string { return kindRequiredReadiness }

// Check implements Caveat.
func (r RequiredReadiness) Check(req Request) error {
	if req.Readiness != "" && slices.Contains(r, req.Readiness) {
		return nil
	}
	return ErrCaveatNotSatisfied
}

// Narrows reports whether every state r allows, parent also allows.
func (r RequiredReadiness) Narrows(parent Caveat) bool {
	p, ok := parent.(RequiredReadiness)
	if !ok {
		return false
	}
	for _, s := range r {
		if !slices.Contains(p, s) {
			return false
		}
	}
	return true
}

func (r RequiredReadiness) encodeValue() (any, error) { return sortedUnique(r), nil }

func decodeRequiredReadiness(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	wire, err := decodeNonEmptyStrings(value)
	if err != nil {
		return nil, err
	}
	return RequiredReadiness(wire), nil
}

func init() { registerCaveat(kindRequiredReadiness, decodeRequiredReadiness) }

// ---- RequireDeclaredDigest ------------------------------------------------

// RequireDeclaredDigest refuses an upload that declared no content address:
// Request.DeclaredDigest must be non-empty.
type RequireDeclaredDigest struct{}

// Kind implements Caveat.
func (RequireDeclaredDigest) Kind() string { return kindRequireDeclaredDigest }

// Check implements Caveat.
func (RequireDeclaredDigest) Check(req Request) error {
	if req.DeclaredDigest == "" {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether parent carries the same requirement.
func (RequireDeclaredDigest) Narrows(parent Caveat) bool {
	_, ok := parent.(RequireDeclaredDigest)
	return ok
}

func (RequireDeclaredDigest) encodeValue() (any, error) { return true, nil }

func decodeRequireDeclaredDigest(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	if err := decodePresenceFlag(value); err != nil {
		return nil, err
	}
	return RequireDeclaredDigest{}, nil
}

func init() { registerCaveat(kindRequireDeclaredDigest, decodeRequireDeclaredDigest) }

// ---- ClientCIDR -----------------------------------------------------------

// ClientCIDR refuses a request from a client address outside this prefix.
// Request.ClientIP is unmapped (a ::ffff:a.b.c.d IPv4-mapped IPv6 address
// becomes plain a.b.c.d) before the containment check, so an IPv4 prefix
// matches a mapped address presented over an IPv6 socket the same way it
// would over a native IPv4 one.
//
// An unset Request.ClientIP is refused explicitly rather than incidentally:
// netip.Prefix.Contains happens to return false for the zero Addr, but
// relying on that would make a forgotten field fail closed only by
// accident, and 0.0.0.0/0 is a prefix for which "contains nothing" reads as
// a bug rather than a decision.
type ClientCIDR netip.Prefix

// Kind implements Caveat.
func (c ClientCIDR) Kind() string { return kindClientCIDR }

// Check implements Caveat.
func (c ClientCIDR) Check(req Request) error {
	addr := req.ClientIP
	if !addr.IsValid() {
		return ErrCaveatNotSatisfied
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !netip.Prefix(c).Contains(addr) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether c's range sits entirely inside parent's: at least
// as specific (bits no smaller) and contained.
func (c ClientCIDR) Narrows(parent Caveat) bool {
	p, ok := parent.(ClientCIDR)
	if !ok {
		return false
	}
	cp, pp := netip.Prefix(c), netip.Prefix(p)
	if cp.Bits() < pp.Bits() {
		return false
	}
	return pp.Contains(cp.Addr())
}

func (c ClientCIDR) encodeValue() (any, error) {
	prefix := netip.Prefix(c)
	if !prefix.IsValid() {
		return nil, errMalformedValue
	}
	// Masked() puts the prefix in its canonical form, so 10.0.0.5/8 and
	// 10.0.0.0/8 — the same range — produce the same signed bytes.
	return prefix.Masked().String(), nil
}

func decodeClientCIDR(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	var s string
	if err := json.Unmarshal(value, &s); err != nil {
		return nil, errMalformedValue
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, errMalformedValue
	}
	if prefix.Masked() != prefix {
		// A non-canonical prefix would re-encode differently from how it
		// arrived, which is the canonicalization hazard cas's Fingerprint
		// existed to work around. Refusing it keeps decode-then-encode a
		// byte-exact identity.
		return nil, errMalformedValue
	}
	return ClientCIDR(prefix), nil
}

func init() { registerCaveat(kindClientCIDR, decodeClientCIDR) }

// ---- DelegationDepth ------------------------------------------------------

// DelegationDepth refuses a request presented through a chain of more than
// this many TOTAL links — DelegationDepth(n) bounds Request.ChainDepth at
// n, which allows up to n-1 derivations beyond the root, not n.
// DelegationDepth(1) means "the root token itself, never derived".
type DelegationDepth int64

// Kind implements Caveat.
func (d DelegationDepth) Kind() string { return kindDelegationDepth }

// Check implements Caveat.
func (d DelegationDepth) Check(req Request) error {
	// ChainDepth's documented minimum is 1 (a never-derived token still has
	// a root link); 0 is unambiguously "nobody populated this field", not a
	// request two derivations deeper than the root. Treating an unpopulated
	// field as automatically satisfying the caveat is the same
	// fail-open-by-forgotten-field hazard domain.ResourcePath's validity
	// guard exists to prevent, so a ChainDepth outside [1, +inf) is refused
	// rather than silently passed.
	//
	// In this module chain.Verify populates the field from the chain it
	// just walked, so the hazard is closed structurally as well. The guard
	// stays because a Request assembled by any other path must fail closed
	// too.
	if req.ChainDepth < 1 || int64(req.ChainDepth) > int64(d) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether d allows no deeper a chain than parent.
func (d DelegationDepth) Narrows(parent Caveat) bool {
	p, ok := parent.(DelegationDepth)
	if !ok {
		return false
	}
	return d <= p
}

func (d DelegationDepth) encodeValue() (any, error) { return int64(d), nil }

func decodeDelegationDepth(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	n, err := decodeNonNegativeInt(value)
	if err != nil {
		return nil, err
	}
	return DelegationDepth(n), nil
}

func init() { registerCaveat(kindDelegationDepth, decodeDelegationDepth) }

// ---- ProcessorAudience ----------------------------------------------------

// ProcessorAudience refuses a request unless Request.ProcessorIdentity (the
// calling processor's opaque identity) exactly matches.
type ProcessorAudience string

// Kind implements Caveat.
func (p ProcessorAudience) Kind() string { return kindProcessorAudience }

// Check implements Caveat.
func (p ProcessorAudience) Check(req Request) error {
	if req.ProcessorIdentity == "" || req.ProcessorIdentity != string(p) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether p names the same processor as parent: an audience
// caveat cannot be redirected to a different processor, only kept.
func (p ProcessorAudience) Narrows(parent Caveat) bool {
	pp, ok := parent.(ProcessorAudience)
	if !ok {
		return false
	}
	return p == pp
}

func (p ProcessorAudience) encodeValue() (any, error) {
	if p == "" {
		return nil, errMalformedValue
	}
	return string(p), nil
}

func decodeProcessorAudience(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	s, err := decodeNonEmptyString(value)
	if err != nil {
		return nil, err
	}
	return ProcessorAudience(s), nil
}

func init() { registerCaveat(kindProcessorAudience, decodeProcessorAudience) }

// ---- Watermark ------------------------------------------------------------

// Watermark restricts a token to serving only the named rendition.
//
// What Check enforces, every time it is checked: the REQUESTED rendition
// (Request.Rendition) must equal this caveat's label exactly. That alone is
// what makes "the gateway must refuse the original through such a link"
// true — a request naming the original (an empty rendition), or any other
// rendition, fails Check and is refused before anything is read or served.
//
// What Watermark does NOT, and structurally cannot, enforce from inside a
// caveat: that the bytes actually stored under that rendition are genuinely
// watermarked. Producing the rendition is the rendition-producing
// processor's job; Watermark only narrows WHICH rendition a request may
// name, and then trusts whatever populated it.
//
// cas compared Request.Resource.SlotPath, a field of CAS's own resource
// model. The label is now opaque, which changes nothing about the guarantee
// above.
type Watermark string

// Kind implements Caveat.
func (w Watermark) Kind() string { return kindWatermark }

// Check implements Caveat. See the type's doc comment for exactly what this
// does and does not guarantee.
func (w Watermark) Check(req Request) error {
	if req.Rendition != string(w) {
		return ErrCaveatNotSatisfied
	}
	return nil
}

// Narrows reports whether w names the same rendition as parent: retargeting
// to a different rendition is neither proven narrower nor wider, so it is
// refused like any other unprovable change.
func (w Watermark) Narrows(parent Caveat) bool {
	p, ok := parent.(Watermark)
	if !ok {
		return false
	}
	return w == p
}

func (w Watermark) encodeValue() (any, error) {
	if w == "" {
		return nil, errMalformedValue
	}
	return string(w), nil
}

func decodeWatermark(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	s, err := decodeNonEmptyString(value)
	if err != nil {
		return nil, err
	}
	return Watermark(s), nil
}

func init() { registerCaveat(kindWatermark, decodeWatermark) }
