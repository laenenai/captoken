package chain

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
	"github.com/laenenai/captoken/reserve"
)

// MintSpec describes the token to mint or derive. The same type serves both
// because a derivation is a mint with a parent: every field means the same
// thing, and what changes is only whether a parent constrains it.
type MintSpec struct {
	// Type is what the token is for. See TokenType.
	Type TokenType
	// Subject is who the token is minted for, opaque.
	Subject domain.Subject
	// Audience is who may accept it. Required on a terminal token; a
	// delegation token may leave it empty, which places no restriction on
	// its descendants' audiences.
	Audience []domain.Audience
	// NotBefore and ExpiresAt bound validity. ExpiresAt is required: a
	// capability with no expiry is a liability, and requiring it means the
	// subsumption rule never has to reason about a missing bound.
	NotBefore time.Time
	ExpiresAt time.Time
	// Permissions is what the token grants. Required and non-empty.
	Permissions domain.PermissionSet
	// Resources is the scopes it covers, union semantics. Required and
	// non-empty.
	Resources []domain.ResourcePath
	// Caveats narrow it further. A derivation must restate every caveat
	// kind its parent carries, with a value at least as restrictive —
	// dropping one is a widening by removal, and is refused.
	Caveats []caveat.Caveat
	// HolderPublicKey binds a caller-supplied Ed25519 key to a delegation
	// token instead of generating one. The caller keeps the private half; the
	// returned Minted.HolderKey is nil. It is refused on a terminal token,
	// which nobody derives from.
	HolderPublicKey ed25519.PublicKey
}

// Minted is a freshly minted or derived token.
type Minted struct {
	// Token is the presentation string: the chain, root first.
	Token string
	// HolderKey is the private key whose public half this token bound in
	// its cnf claim, and which the holder needs in order to derive from
	// it. It is nil for a terminal token, which cannot be derived from, and
	// for a delegation minted with MintSpec.HolderPublicKey, where the
	// caller already holds the private half.
	//
	// It is returned beside the token rather than inside it, and that is
	// the whole key-custody story: no private key is ever part of a
	// token's serialized form, so a recipient of the bytes alone can never
	// derive, and the minter hands this to the holder over whatever
	// confidential channel it already has.
	HolderKey ed25519.PrivateKey
}

// ---- minting --------------------------------------------------------------

// MinterConfig configures NewMinter.
type MinterConfig struct {
	// Issuer is stamped into every link this minter signs.
	Issuer domain.Issuer
	// RootKey signs root links. Its public half is what a verifier must be
	// configured with. Any crypto.Signer whose public key is a usable
	// Ed25519 key is accepted, so the private half may live in an HSM or KMS.
	RootKey crypto.Signer
	// Schema is the consumer's declared resource hierarchy.
	Schema domain.ResourceSchema
	// Clock supplies iat. Defaults to domain.SystemClock.
	Clock domain.Clock
}

// Minter mints root tokens.
type Minter struct {
	issuer  domain.Issuer
	rootKey crypto.Signer
	schema  domain.ResourceSchema
	clock   domain.Clock
}

// NewMinter validates cfg and returns a Minter.
func NewMinter(cfg MinterConfig) (*Minter, error) {
	if _, err := domain.ParseID("issuer", string(cfg.Issuer)); err != nil {
		return nil, configError(err)
	}
	if _, err := signerPublicKey(cfg.RootKey); err != nil {
		return nil, configError(err)
	}
	if cfg.Schema.IsZero() {
		return nil, configError(fmt.Errorf("%w: no resource schema", domain.ErrMalformedResourceSchema))
	}
	clock, err := checkedClock(cfg.Clock)
	if err != nil {
		return nil, configError(err)
	}
	return &Minter{issuer: cfg.Issuer, rootKey: cfg.RootKey, schema: cfg.Schema, clock: clock}, nil
}

// Mint signs a new root link: the start of a chain, with no parent to
// narrow against.
//
// The chain's identifier is the root link's own token id, which every
// descendant carries verbatim. That is what makes revocation chain-wide and
// byte-identical in every descendant — revoke this id and every token ever
// derived from this root dies.
func (m *Minter) Mint(spec MintSpec) (Minted, error) {
	if m == nil || isNilValue(m.rootKey) || isNilValue(m.clock) || m.schema.IsZero() {
		return Minted{}, fmt.Errorf("%w: minter is not initialized; use NewMinter", ErrInvalidToken)
	}
	id, err := domain.NewTokenID()
	if err != nil {
		return Minted{}, err
	}
	c, holder, err := buildClaims(spec, m.issuer, domain.ChainID(id), id, "", m.clock.Now())
	if err != nil {
		return Minted{}, err
	}
	// The same canonical decode a verifier performs. Mint must not sign a
	// claim set that its own verifier would refuse: an empty subject, an
	// invalid audience, a malformed permission or a path from a different
	// schema are all construction errors, and discovering them at the
	// holder is too late.
	if _, err := decodeGrantForSubsumption(c, m.schema); err != nil {
		return Minted{}, err
	}
	token, err := signLink(c, m.rootKey)
	if err != nil {
		return Minted{}, err
	}
	presented := present([]string{token})
	if len(presented) > MaxPresentationBytes {
		return Minted{}, fmt.Errorf("%w: presentation exceeds %d bytes", ErrInvalidToken, MaxPresentationBytes)
	}
	return Minted{Token: presented, HolderKey: holder}, nil
}

// RootPublicKey returns the public half of the minter's root key, which is
// what a verifier is configured with.
func (m *Minter) RootPublicKey() ed25519.PublicKey {
	if m == nil {
		return nil
	}
	pub, err := signerPublicKey(m.rootKey)
	if err != nil {
		return nil
	}
	return slices.Clone(pub)
}

// ---- deriving -------------------------------------------------------------

// DeriverConfig configures NewDeriver.
type DeriverConfig struct {
	// Schema is the consumer's declared resource hierarchy.
	Schema domain.ResourceSchema
	// Clock supplies iat. Defaults to domain.SystemClock.
	Clock domain.Clock
	// MaxLinks bounds the parent chain's length. Defaults to
	// DefaultMaxLinks.
	MaxLinks int
}

// Deriver appends a narrower link to a chain, offline.
type Deriver struct {
	schema   domain.ResourceSchema
	clock    domain.Clock
	maxLinks int
}

// NewDeriver validates cfg and returns a Deriver.
func NewDeriver(cfg DeriverConfig) (*Deriver, error) {
	if cfg.Schema.IsZero() {
		return nil, configError(fmt.Errorf("%w: no resource schema", domain.ErrMalformedResourceSchema))
	}
	clock, err := checkedClock(cfg.Clock)
	if err != nil {
		return nil, configError(err)
	}
	maxLinks, err := boundMaxLinks(cfg.MaxLinks)
	if err != nil {
		return nil, configError(err)
	}
	return &Deriver{schema: cfg.Schema, clock: clock, maxLinks: maxLinks}, nil
}

// Derive appends a narrower link to presented, signed with holderKey — the
// private key whose public half the chain's last link bound in its cnf
// claim.
//
// It needs no root public key and makes no call to the issuer, which is the
// point: a holder narrows what they hold offline. It therefore does NOT
// check the parent chain's signatures, because the holder may not have the
// root key to check them with — a holder who was given a garbage chain
// derives from garbage, which verifies nowhere, and that is a usability
// failure rather than a security one.
//
// It DOES check that the new link narrows its parent, and refuses a widening
// before signing it. That check is a courtesy, not the guarantee: the
// guarantee is the verifier's, which re-checks subsumption at every link on
// every verification. A minter that forgot to call this would be refused by
// the verifier rather than trusted — which is exactly what cas's Narrows,
// consulted only at mint time, could not promise.
func (d *Deriver) Derive(presented string, holderKey crypto.Signer, spec MintSpec) (Minted, error) {
	if d == nil || isNilValue(d.clock) || d.schema.IsZero() || d.maxLinks <= 0 {
		return Minted{}, fmt.Errorf("%w: deriver is not initialized; use NewDeriver", ErrInvalidToken)
	}
	parts, err := splitPresentation(presented, d.maxLinks)
	if err != nil {
		return Minted{}, err
	}
	if len(parts)+1 > d.maxLinks {
		return Minted{}, fmt.Errorf("%w: chain is already at its maximum length", ErrInvalidToken)
	}
	parent, err := decodeLink(parts[len(parts)-1], d.schema, true)
	if err != nil {
		return Minted{}, err
	}
	if TokenType(parent.claims.Type) != TypeDelegation {
		return Minted{}, fmt.Errorf("%w: parent authorises no derivation", ErrInvalidToken)
	}
	holderPub, err := signerPublicKey(holderKey)
	if err != nil {
		return Minted{}, err
	}
	if subtle.ConstantTimeCompare(holderPub, parent.confirm) != 1 {
		return Minted{}, fmt.Errorf("%w: holder key is not the key the parent bound", ErrInvalidToken)
	}

	id, err := domain.NewTokenID()
	if err != nil {
		return Minted{}, err
	}
	c, holder, err := buildClaims(
		spec,
		domain.Issuer(parent.claims.Issuer),
		domain.ChainID(parent.claims.ChainID),
		id,
		parentHash(parent.signing),
		d.clock.Now(),
	)
	if err != nil {
		return Minted{}, err
	}

	child, err := decodeGrantForSubsumption(c, d.schema)
	if err != nil {
		return Minted{}, err
	}
	if !child.Narrows(parent.grant) || !audienceNarrows(c.Audience, parent.claims.Audience) {
		return Minted{}, fmt.Errorf("%w: derivation would not narrow its parent", ErrInvalidToken)
	}

	token, err := signLink(c, holderKey)
	if err != nil {
		return Minted{}, err
	}
	out := present(append(slices.Clone(parts), token))
	if len(out) > MaxPresentationBytes {
		return Minted{}, fmt.Errorf("%w: presentation exceeds %d bytes", ErrInvalidToken, MaxPresentationBytes)
	}
	return Minted{Token: out, HolderKey: holder}, nil
}

// decodeGrantForSubsumption re-reads freshly built claims as a Grant, so
// that the narrowing check compares the two sides the same way the verifier
// will. Comparing the spec directly against the parent would compare a
// pre-canonicalization value against a decoded one, and the one difference
// that matters — a bound truncated to a whole second — is exactly the kind
// of mismatch that makes a mint-time check and a verify-time check
// disagree.
func decodeGrantForSubsumption(c claims, schema domain.ResourceSchema) (caveat.Grant, error) {
	return grantFrom(c, schema)
}

// ---- verifying ------------------------------------------------------------

// VerifierConfig configures NewVerifier.
type VerifierConfig struct {
	// Issuer is the only issuer this verifier accepts. Every link's "iss"
	// must equal it.
	Issuer domain.Issuer
	// RootKeys are the trusted root public keys. Non-empty, and TRIED IN
	// TURN: the token plays no part in choosing which one is used. There
	// is deliberately no "kid" in the format for a key to be looked up by,
	// because a verifier that reads the token to decide which key to check
	// the token with is where the algorithm- and key-confusion families
	// begin. Several keys are accepted so that a root key can be rotated
	// without a flag day.
	RootKeys []ed25519.PublicKey
	// Audience is this verifier's own identity. The terminal link's "aud"
	// must contain it.
	//
	// This is the claim the partition's soundness rests on. A redemption
	// token's audience is the issuer's reservation service, so a
	// third-party verifier refuses it here — on a claim RFC 7519 requires
	// be checked and which every mainstream library does check correctly,
	// unlike "crit".
	Audience domain.Audience
	// Schema is the consumer's declared resource hierarchy.
	Schema domain.ResourceSchema
	// Clock supplies "now" for verification. Request.Now is ignored. Defaults
	// to domain.SystemClock.
	Clock domain.Clock
	// MaxLinks bounds a presented chain's length. Defaults to
	// DefaultMaxLinks.
	MaxLinks int
	// Reservations reads the counters a redemption token's stateful
	// caveats are checked against. A nil Reservations means this verifier
	// cannot verify a redemption token and refuses one — which is the
	// fail-closed outcome the charter's two-surface design needs: a
	// verifier that cannot supply the counters refuses rather than
	// skipping the check.
	Reservations reserve.Counters
	// Revocations is consulted for the chain's revocation identifier. It is
	// required unless NoRevocation says this deployment has deliberately
	// chosen not to revoke. A nil Revocations is a construction error, not a
	// silent skip: a revoked chain would otherwise verify forever.
	Revocations reserve.Revocations
	// NoRevocation opts out of revocation checking explicitly. It must be
	// false when Revocations is set, so omitting both cannot be mistaken for
	// a deliberate choice.
	NoRevocation bool
}

// Verifier verifies presented chains.
type Verifier struct {
	issuer      domain.Issuer
	rootKeys    []ed25519.PublicKey
	audience    domain.Audience
	schema      domain.ResourceSchema
	clock       domain.Clock
	maxLinks    int
	counters    reserve.Counters
	revocations reserve.Revocations

	// weak disables individual guards. It is test-only, and the ZERO VALUE
	// IS FULLY STRICT — every field means "do not perform this check", so
	// production code never sets it and cannot weaken anything by
	// forgetting to. The mutation test in subsumption_test.go is the only
	// writer: it removes one guard at a time and asserts that the specific
	// attack the suite attributes to that guard stops being refused, which
	// is how the adversarial suite is shown to have teeth.
	weak weakened
}

// weakened names the verification guards individually. See Verifier.weak.
type weakened struct {
	permissions       bool
	resources         bool
	window            bool
	caveats           bool
	parentHash        bool
	typeOrder         bool
	chainID           bool
	issuer            bool
	audience          bool
	statefulPlacement bool
	version           bool
	signature         bool
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if _, err := domain.ParseID("issuer", string(cfg.Issuer)); err != nil {
		return nil, configError(err)
	}
	if _, err := domain.ParseID("audience", string(cfg.Audience)); err != nil {
		return nil, configError(err)
	}
	if len(cfg.RootKeys) == 0 {
		return nil, configError(fmt.Errorf("no trusted root keys"))
	}
	keys := make([]ed25519.PublicKey, len(cfg.RootKeys))
	for i, k := range cfg.RootKeys {
		if err := validatePublicKey(k); err != nil {
			return nil, configError(fmt.Errorf("a trusted root key is unusable: %w", err))
		}
		keys[i] = slices.Clone(k)
	}
	if isNilValue(cfg.Reservations) {
		cfg.Reservations = nil
	}
	if isNilValue(cfg.Revocations) {
		cfg.Revocations = nil
	}
	if cfg.Revocations == nil && !cfg.NoRevocation {
		return nil, configError(fmt.Errorf("%w: set Revocations or NoRevocation", ErrNoRevocationBackend))
	}
	if cfg.Revocations != nil && cfg.NoRevocation {
		return nil, configError(fmt.Errorf("%w: Revocations and NoRevocation are mutually exclusive", ErrNoRevocationBackend))
	}
	if cfg.Schema.IsZero() {
		return nil, configError(fmt.Errorf("%w: no resource schema", domain.ErrMalformedResourceSchema))
	}
	clock, err := checkedClock(cfg.Clock)
	if err != nil {
		return nil, configError(err)
	}
	maxLinks, err := boundMaxLinks(cfg.MaxLinks)
	if err != nil {
		return nil, configError(err)
	}
	return &Verifier{
		issuer:      cfg.Issuer,
		rootKeys:    keys,
		audience:    cfg.Audience,
		schema:      cfg.Schema,
		clock:       clock,
		maxLinks:    maxLinks,
		counters:    cfg.Reservations,
		revocations: cfg.Revocations,
	}, nil
}

// Verified is what a successful verification establishes.
type Verified struct {
	// Type is the terminal link's token type.
	Type TokenType
	// ChainID is the chain's identifier, and its revocation key.
	ChainID domain.ChainID
	// Subject is the terminal link's subject.
	Subject domain.Subject
	// Depth is the number of links presented, the root included.
	Depth int
	// Permissions is the chain's effective grant: the INTERSECTION of
	// every link's, not the terminal link's claim about it. Subsumption
	// means the two agree, and computing the intersection anyway is what
	// makes a widening link powerless as well as refused.
	Permissions domain.PermissionSet
	// TerminalResources is the TERMINAL link's scopes, which subsumption
	// has established to be inside every ancestor's. It is deliberately not
	// called Resources: the chain's effective authority is the intersection
	// of every link's scopes, and a consumer that needs that must compute it
	// from the grants rather than assume this field is the whole scope.
	TerminalResources []domain.ResourcePath
	// ExpiresAt is the earliest expiry across the chain.
	ExpiresAt time.Time
}

// Verify checks presented against the verifier's trusted roots and decides
// whether it authorises req at the verifier's clock's current time.
//
// Request.Now is ignored: the verifier owns the clock, so a caller cannot
// make an expired token valid by presenting an old time. Use VerifyAt for a
// test or replay that needs a specific instant.
//
// What it establishes, in order, and all of it before any authorization
// question is asked:
//
//  1. the presentation is this format, and no longer than MaxLinks;
//  2. every link's header is exactly {alg: EdDSA, typ: captoken+jwt} — no
//     kid, no jwk, no crit, nothing to follow and nothing to interpret;
//  3. every link's claim set is this format's version, with no unknown
//     member and no member named twice;
//  4. every link names the configured issuer, and carries the root link's
//     token id as its chain id;
//  5. the root link verifies under one of the configured root keys, tried
//     in turn, and every other link verifies under the key its parent
//     bound in cnf;
//  6. every link after the root commits to exactly one parent, by the
//     SHA-256 of that parent's signing input;
//  7. every interior link is a delegation token and the terminal link
//     authorises an operation — which is what makes a truncated chain
//     powerless with no seal and no proof;
//  8. every link narrows its parent in every dimension this module orders;
//  9. no stateful caveat appears anywhere but on a terminal redemption
//     link;
//  10. the terminal link's audience contains this verifier's own;
//  11. the chain is not revoked;
//  12. for a redemption token, the counters are read from the reservation
//     port, and a verifier without one refuses;
//  13. and finally the request is checked against the INTERSECTION of
//     every link's conditions.
//
// On any failure it returns ErrInvalidToken, or
// caveat.ErrCaveatNotSatisfied if the chain was valid and the request was
// not permitted — deliberately without saying which check failed.
func (v *Verifier) Verify(ctx context.Context, presented string, req caveat.Request) (Verified, error) {
	if err := v.ready(); err != nil {
		return Verified{}, sanitize(err)
	}
	return v.verifyAt(ctx, presented, req, v.clock.Now())
}

// VerifyAt is Verify at an explicit instant. It exists for tests and for a
// verifier replaying a recorded decision; the instant must be non-zero.
// Production callers should use Verify, which reads the verifier's clock.
func (v *Verifier) VerifyAt(ctx context.Context, presented string, req caveat.Request, now time.Time) (Verified, error) {
	if err := v.ready(); err != nil {
		return Verified{}, sanitize(err)
	}
	if now.IsZero() {
		return Verified{}, fmt.Errorf("%w: zero verification time", ErrInvalidToken)
	}
	return v.verifyAt(ctx, presented, req, now)
}

func (v *Verifier) ready() error {
	if v == nil || len(v.rootKeys) == 0 || isNilValue(v.clock) || v.schema.IsZero() || v.maxLinks <= 0 {
		return fmt.Errorf("%w: verifier is not initialized; use NewVerifier", ErrInvalidToken)
	}
	return nil
}

func (v *Verifier) verifyAt(ctx context.Context, presented string, req caveat.Request, now time.Time) (Verified, error) {
	verified, err := v.verify(ctx, presented, req, now)
	return verified, sanitize(err)
}

// sanitize reduces any refusal that names a reason to the bare sentinel.
//
// The reasons exist — every refusal inside this package carries one, and
// they are what makes the internal tests readable — but they must not cross
// the boundary. A verifier that tells a presenter WHICH of a dozen checks
// their forgery failed has handed them a dimension to search along, and the
// search is cheap: flip one field, read the message, repeat. cas drew the
// same line in the same place, wrapping detail into its parse errors and
// returning its verification sentinel bare.
//
// ErrNotAuthorizing is the one preserved distinction, and it is not an
// oracle: it says only that the presenter's own terminal link is a
// delegation token, which the presenter already knows, since they chose
// which links to present.
func sanitize(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotAuthorizing):
		return ErrNotAuthorizing
	case errors.Is(err, ErrInvalidToken):
		return ErrInvalidToken
	default:
		return err
	}
}

func (v *Verifier) verify(ctx context.Context, presented string, req caveat.Request, now time.Time) (Verified, error) {
	parts, err := splitPresentation(presented, v.maxLinks)
	if err != nil {
		return Verified{}, err
	}

	links := make([]link, len(parts))
	for i, part := range parts {
		l, derr := decodeLink(part, v.schema, !v.weak.version)
		if derr != nil {
			return Verified{}, derr
		}
		links[i] = l
	}
	leaf := links[len(links)-1]

	if err := v.checkIdentity(links); err != nil {
		return Verified{}, err
	}
	if err := v.checkLinkage(links); err != nil {
		return Verified{}, err
	}
	if err := v.checkTypes(links); err != nil {
		return Verified{}, err
	}
	for i := 1; i < len(links); i++ {
		if err := v.subsumes(links[i], links[i-1]); err != nil {
			return Verified{}, err
		}
	}
	if err := v.checkStatefulPlacement(links); err != nil {
		return Verified{}, err
	}
	if !v.weak.audience && !slices.Contains(leaf.claims.Audience, string(v.audience)) {
		return Verified{}, fmt.Errorf("%w: not this audience", ErrInvalidToken)
	}

	chainID := domain.ChainID(links[0].claims.ChainID)
	if v.revocations != nil {
		revoked, rerr := v.revocations.IsRevoked(ctx, chainID)
		if rerr != nil {
			if errors.Is(rerr, context.Canceled) || errors.Is(rerr, context.DeadlineExceeded) {
				return Verified{}, rerr
			}
			return Verified{}, ErrBackend
		}
		if revoked {
			return Verified{}, reserve.ErrRevoked
		}
	}

	if TokenType(leaf.claims.Type) == TypeRedemption {
		if v.counters == nil {
			return Verified{}, reserve.ErrNoReservationService
		}
		snapshot, cerr := v.counters.Read(ctx, chainID)
		if cerr != nil {
			if errors.Is(cerr, reserve.ErrNoReservationService) {
				return Verified{}, reserve.ErrNoReservationService
			}
			if errors.Is(cerr, context.Canceled) || errors.Is(cerr, context.DeadlineExceeded) {
				return Verified{}, cerr
			}
			return Verified{}, ErrBackend
		}
		req.UsesBefore = snapshot.Uses
		req.FirstUsedAt = snapshot.FirstUsedAt
		req.BytesTransferredBefore = snapshot.BytesTransferred
	}

	// The verifier populates ChainDepth from the chain it has just walked
	// rather than trusting the caller to, which closes the forgotten-field
	// fail-open cas's equivalent field invited. The DelegationDepth caveat
	// still refuses a depth below 1, so a Request assembled by any other
	// path fails closed too.
	req.ChainDepth = len(links)
	req.Now = now

	grants := make([]caveat.Grant, len(links))
	for i, l := range links {
		grants[i] = l.grant
	}
	if err := caveat.CheckAll(grants, req); err != nil {
		if errors.Is(err, caveat.ErrUnknownCaveat) || errors.Is(err, caveat.ErrEmptyChain) {
			return Verified{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}
		return Verified{}, err
	}

	effective := links[0].grant.Permissions
	earliest := links[0].grant.ExpiresAt
	for _, l := range links[1:] {
		effective = effective.Intersect(l.grant.Permissions)
		if l.grant.ExpiresAt.Before(earliest) {
			earliest = l.grant.ExpiresAt
		}
	}

	return Verified{
		Type:              TokenType(leaf.claims.Type),
		ChainID:           chainID,
		Subject:           leaf.grant.Subject,
		Depth:             len(links),
		Permissions:       effective,
		TerminalResources: leaf.grant.Resources,
		ExpiresAt:         earliest,
	}, nil
}

// checkIdentity enforces that every link belongs to the same chain, issued
// by the configured issuer, with a distinct token id of its own.
func (v *Verifier) checkIdentity(links []link) error {
	if !v.weak.issuer {
		for _, l := range links {
			if l.claims.Issuer != string(v.issuer) {
				return fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
			}
		}
	}
	if v.weak.chainID {
		return nil
	}
	// The root link's own token id IS the chain id. That is what makes the
	// identifier byte-identical in every descendant and therefore a
	// chain-wide revocation key; a link free to name its own chain id
	// could evade its ancestor's revocation.
	if links[0].claims.ChainID != links[0].claims.TokenID {
		return fmt.Errorf("%w: root link does not name itself as its chain", ErrInvalidToken)
	}
	seen := make(map[string]struct{}, len(links))
	for _, l := range links {
		if l.claims.ChainID != links[0].claims.ChainID {
			return fmt.Errorf("%w: chain id mismatch", ErrInvalidToken)
		}
		if _, dup := seen[l.claims.TokenID]; dup {
			return fmt.Errorf("%w: duplicate token id", ErrInvalidToken)
		}
		seen[l.claims.TokenID] = struct{}{}
	}
	return nil
}

// checkLinkage verifies every signature and every parent hash.
func (v *Verifier) checkLinkage(links []link) error {
	for i, l := range links {
		if i == 0 {
			if !v.weak.parentHash && l.claims.ParentHash != nil {
				return fmt.Errorf("%w: root link names a parent", ErrInvalidToken)
			}
			if v.weak.signature {
				continue
			}
			if err := v.verifyUnderAnyRoot(l.compact); err != nil {
				return err
			}
			continue
		}

		parent := links[i-1]
		if !v.weak.signature {
			if parent.confirm == nil {
				// Only a delegation link binds a key, so only a delegation
				// link can be a parent. Without a bound key there is
				// nothing to check the child's signature against, which is
				// a refusal rather than a check to skip.
				return fmt.Errorf("%w: parent binds no key", ErrInvalidToken)
			}
			if err := verifySignature(l.compact, parent.confirm); err != nil {
				return err
			}
		}
		if !v.weak.parentHash && (l.claims.ParentHash == nil || *l.claims.ParentHash != parentHash(parent.signing)) {
			return fmt.Errorf("%w: parent hash mismatch", ErrInvalidToken)
		}
	}
	return nil
}

// verifyUnderAnyRoot tries every trusted root key in turn.
//
// Trying them all, rather than selecting one, is the point: the token
// carries nothing that chooses a key. The cost is one Ed25519 verification
// per configured key, which is why MaxLinks and the number of root keys are
// both small and bounded.
func (v *Verifier) verifyUnderAnyRoot(compact string) error {
	for _, key := range v.rootKeys {
		if err := verifySignature(compact, key); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: root signature does not verify", ErrInvalidToken)
}

// checkTypes enforces the partition: every interior link is a delegation
// token, and the terminal link authorises an operation.
//
// This is where a truncated chain dies. Every proper prefix of a chain ends
// in a delegation link, and a delegation link authorises nothing — so
// presenting a prefix to recover an ancestor's wider authority yields a
// refusal, with no seal, no proof and no private key anywhere in the wire
// form. See this package's doc comment.
func (v *Verifier) checkTypes(links []link) error {
	if v.weak.typeOrder {
		return nil
	}
	for _, l := range links[:len(links)-1] {
		if TokenType(l.claims.Type) != TypeDelegation {
			return fmt.Errorf("%w: an interior link is not a delegation token", ErrInvalidToken)
		}
	}
	if !TokenType(links[len(links)-1].claims.Type).terminal() {
		return fmt.Errorf("%w: %w", ErrInvalidToken, ErrNotAuthorizing)
	}
	return nil
}

// checkStatefulPlacement enforces that a caveat requiring a server-side
// reservation appears only where one can be supplied: on the terminal link
// of a chain, and only when that link is a redemption token.
//
// This is the structural half of the charter's partition. Because a
// redemption token's audience is the issuer's own reservation service, a
// third-party verifier never accepts one — so a stateful caveat can never
// reach a verifier that is unable to evaluate it, and the "naive but
// correct" verification a stock JWT library performs is sound rather than
// merely usually right.
func (v *Verifier) checkStatefulPlacement(links []link) error {
	if v.weak.statefulPlacement {
		return nil
	}
	for i, l := range links {
		terminalRedemption := i == len(links)-1 && TokenType(l.claims.Type) == TypeRedemption
		for _, c := range l.grant.Caveats {
			if caveat.IsStatefulKind(c.Kind()) && !terminalRedemption {
				return fmt.Errorf("%w: a stateful caveat on a token that cannot carry one", ErrInvalidToken)
			}
		}
	}
	return nil
}

// subsumes enforces the central invariant for one link against its parent.
func (v *Verifier) subsumes(child, parent link) error {
	switch {
	case !v.weak.permissions && !child.grant.NarrowsPermissions(parent.grant):
		return fmt.Errorf("%w: permissions widen", ErrInvalidToken)
	case !v.weak.resources && !child.grant.NarrowsResources(parent.grant):
		return fmt.Errorf("%w: resource scope widens", ErrInvalidToken)
	case !v.weak.window && !child.grant.NarrowsWindow(parent.grant):
		return fmt.Errorf("%w: validity window widens", ErrInvalidToken)
	case !v.weak.caveats && !child.grant.NarrowsCaveats(parent.grant):
		return fmt.Errorf("%w: caveats widen", ErrInvalidToken)
	case !v.weak.audience && !audienceNarrows(child.claims.Audience, parent.claims.Audience):
		return fmt.Errorf("%w: audience widens", ErrInvalidToken)
	default:
		return nil
	}
}

// audienceNarrows reports whether child's audience list is within parent's.
// A parent with no audience places no restriction, so any child audience is
// within it; a parent with one requires the child's to be a subset of it.
func audienceNarrows(child, parent []string) bool {
	if len(parent) == 0 {
		return true
	}
	for _, aud := range child {
		if !slices.Contains(parent, aud) {
			return false
		}
	}
	return len(child) > 0
}

// ---- shared ---------------------------------------------------------------

// buildClaims assembles and canonicalizes one link's claim set. parentHash
// is empty for a root link. It returns the private key a delegation link's
// holder needs, or nil for a terminal link.
func buildClaims(
	spec MintSpec,
	issuer domain.Issuer,
	chainID domain.ChainID,
	id domain.TokenID,
	parent string,
	now time.Time,
) (claims, ed25519.PrivateKey, error) {
	if !spec.Type.valid() {
		return claims{}, nil, fmt.Errorf("%w: unknown token type", ErrInvalidToken)
	}
	if spec.ExpiresAt.IsZero() {
		return claims{}, nil, fmt.Errorf("%w: no expiry", ErrInvalidToken)
	}
	if len(spec.Permissions) == 0 {
		return claims{}, nil, fmt.Errorf("%w: grants no permission", ErrInvalidToken)
	}
	if len(spec.Resources) == 0 {
		return claims{}, nil, fmt.Errorf("%w: names no resource", ErrInvalidToken)
	}
	if spec.Type.terminal() && len(spec.Audience) == 0 {
		return claims{}, nil, fmt.Errorf("%w: a terminal token must name an audience", ErrInvalidToken)
	}
	if spec.HolderPublicKey != nil && spec.Type != TypeDelegation {
		return claims{}, nil, fmt.Errorf("%w: a terminal token has no holder key", ErrInvalidToken)
	}
	for _, c := range spec.Caveats {
		if c == nil {
			return claims{}, nil, fmt.Errorf("%w: nil caveat", ErrInvalidToken)
		}
		if caveat.HasStandardClaim(c.Kind()) {
			// The four dimensions carried as exp, nbf, prm and res may not
			// also be cav entries: docs/wire-format.md requires a verifier
			// to refuse one that appears there, so minting one would issue
			// a token every conforming third-party verifier rejects. They
			// are set through MintSpec's own fields instead.
			return claims{}, nil, fmt.Errorf("%w: a standard claim cannot be a caveat entry", ErrInvalidToken)
		}
		if caveat.IsStatefulKind(c.Kind()) && spec.Type != TypeRedemption {
			// The partition, enforced at mint as well as at verify. A
			// caveat that needs a counter read inside the operation's
			// transaction can only be checked by the party holding the
			// counter, so it may only appear on the token type that party
			// redeems.
			return claims{}, nil, fmt.Errorf("%w: a stateful caveat needs a redemption token", ErrInvalidToken)
		}
	}

	expires := domain.JWTNotAfter(spec.ExpiresAt)
	c := claims{
		Version:   FormatVersion,
		Type:      string(spec.Type),
		Issuer:    string(issuer),
		Subject:   string(spec.Subject),
		TokenID:   string(id),
		ChainID:   string(chainID),
		IssuedAt:  domain.JWTNotAfter(now).Unix(),
		ExpiresAt: expires.Unix(),
	}
	if !spec.NotBefore.IsZero() {
		nbf := domain.JWTNotBefore(spec.NotBefore).Unix()
		if nbf >= c.ExpiresAt {
			return claims{}, nil, fmt.Errorf("%w: validity window is empty", ErrInvalidToken)
		}
		c.NotBefore = &nbf
	}
	if len(spec.Audience) > 0 {
		aud := make([]string, len(spec.Audience))
		for i, a := range spec.Audience {
			aud[i] = string(a)
		}
		slices.Sort(aud)
		c.Audience = slices.Compact(aud)
	}

	perms := spec.Permissions.Sorted()
	c.Permissions = make([]string, len(perms))
	for i, p := range perms {
		c.Permissions[i] = string(p)
	}

	resources, err := caveat.EncodePaths(spec.Resources)
	if err != nil {
		return claims{}, nil, fmt.Errorf("%w: malformed resource scope", ErrInvalidToken)
	}
	c.Resources = resources

	if len(spec.Caveats) > 0 {
		entries, cerr := caveat.EncodeAll(spec.Caveats)
		if cerr != nil {
			return claims{}, nil, fmt.Errorf("%w: malformed caveat", ErrInvalidToken)
		}
		c.Caveats = entries
	}
	if parent != "" {
		c.ParentHash = &parent
	}

	if spec.Type != TypeDelegation {
		return c, nil, nil
	}
	if spec.HolderPublicKey != nil {
		jwk, err := encodeJWK(spec.HolderPublicKey)
		if err != nil {
			return claims{}, nil, err
		}
		c.Confirmation = &confirmation{JWK: jwk}
		return c, nil, nil
	}
	next, err := GenerateKey(nil)
	if err != nil {
		return claims{}, nil, err
	}
	jwk, err := encodeJWK(next.Public)
	if err != nil {
		return claims{}, nil, err
	}
	c.Confirmation = &confirmation{JWK: jwk}
	return c, next.Private, nil
}

// configError marks a constructor refusal as a configuration error while
// preserving the underlying sentinel for errors.Is.
func configError(err error) error {
	// A constructor failure must not also match ErrInvalidToken: that would
	// make a startup mistake look like hostile traffic to a caller's metrics
	// or alerting. Keep the cause as text; retain other sentinels.
	if errors.Is(err, ErrInvalidToken) {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, err.Error())
	}
	return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
}

// checkedClock returns a usable clock, defaulting an omitted one to the
// system clock. A typed nil is a construction error rather than a panic at
// first use.
func checkedClock(c domain.Clock) (domain.Clock, error) {
	if c == nil {
		return domain.SystemClock{}, nil
	}
	if isNilValue(c) {
		return nil, fmt.Errorf("%w: clock is nil", ErrInvalidToken)
	}
	return c, nil
}

// boundMaxLinks validates a configured MaxLinks.
func boundMaxLinks(n int) (int, error) {
	switch {
	case n == 0:
		return DefaultMaxLinks, nil
	case n < 1 || n > MaxMaxLinks:
		return 0, fmt.Errorf("%w: MaxLinks out of range", ErrInvalidToken)
	default:
		return n, nil
	}
}
