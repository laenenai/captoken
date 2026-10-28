// Package caveat is captoken's typed caveat vocabulary: sixteen narrowing
// conditions, the request facts they are checked against, and the
// intersection rule that makes a chain's effective authority the AND of
// every link in it.
//
// It is cas/internal/token's caveat layer, carried across. The semantics
// are the ones cas's 885 lines of tests pinned, and those tests came with
// it; what changed is only what had to, and each change is recorded at the
// declaration it affects.
//
// # Invariants, every one of which is a decision rather than an accident
//
//   - **An unknown caveat kind fails closed.** A verifier that ignores a
//     condition it does not understand is a bypass, not a tolerant reader.
//     CheckAll re-checks every kind against the registry even for a chain
//     a verifier has already decoded, so any other path that assembles a
//     Grant in memory gets the same guarantee.
//   - **A refusal names nothing.** Not the caveat, not a value from the
//     caveat, not a value from the request: a verifier that explains why a
//     request was refused hands an attacker a dimension to search along.
//     The one sentinel a caller gets is ErrCaveatNotSatisfied.
//   - **A length bound fails closed on an unknown length.**
//     Request.ContentLength == -1 (a chunked request, say) refuses, because
//     a caveat that cannot verify a bound does not grant it by default.
//   - **AllowedContentTypes matches the SNIFFED type, never a declared
//     header**, and compares the whole string verbatim, so smuggled MIME
//     parameters are refused with no special-case logic.
//   - **The three stateful caveats read counters they never advance.** The
//     caller reads the counter, calls CheckAll inside the same transaction
//     as the operation, and persists the advance only once the operation
//     succeeds, so a failed upload cannot consume a use or a byte
//     allowance. See TestStatefulCaveats_DoNotAdvanceWhenTheOperationFails.
//   - **ResourceScope keeps a structured comparison.** The Biscuit spike
//     demonstrated that flattening a resource reference to a string makes
//     containment a .starts_with, which matched the scope "fs/a" against
//     its sibling "fs/ab". domain.ResourcePath compares segment by segment
//     and cannot express that.
//
// # What changed from cas, and why
//
//   - cas's domain.ResourceRef and its closed domain.Permission enumeration
//     are CAS's resource model. The charter forbids this module from
//     knowing a consumer's, so a resource is a domain.ResourcePath over a
//     schema the consumer declares, and a permission is an opaque label.
//     domain.Readiness and domain.ContentAddress likewise become opaque
//     strings on Request.
//   - cas's Block.Resources list and its single-scope ResourceScope caveat
//     were the same dimension said twice. ResourceScope now holds a set
//     with union semantics, which is what Block.Resources meant, and two
//     such caveats intersect, which is what CheckAll's loop already did.
//   - cas's Watermark compared Request.Resource.SlotPath, a field of CAS's
//     own model. It now compares Request.Rendition, an opaque label, and
//     guarantees exactly as much as it did before — which slot a request
//     may name, never that the bytes there are watermarked.
//
// The suite in captokentest, not this package's interfaces, is the
// authoritative description of the contract's edge-case behaviour.
package caveat

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/laenenai/captoken/domain"
)

// ErrCaveatNotSatisfied is returned by a caveat's Check method, and by
// CheckAll, when a request does not satisfy a token's caveats. It never
// names which caveat failed, and never carries any value from the caveat or
// the request: a verifier that explains why a request was refused hands an
// attacker a dimension to search along.
//
// Nothing wraps it with further detail. That is not an oversight to be
// tidied up later — a wrapped cause is an oracle, and the one place a
// refusal's reason may be recorded is the issuer's own logs, never the
// value handed back across the trust boundary.
var ErrCaveatNotSatisfied = errors.New("caveat not satisfied")

// ErrUnknownCaveat is returned when a caveat kind is not one this build
// recognizes, or when a caveat value is nil. It is deliberately distinct
// from ErrCaveatNotSatisfied: "I do not understand this condition" and
// "this condition is not met" are both refusals, but only the first one is
// a bug in somebody's build, and an operator needs to be able to tell them
// apart in their own logs. Neither names the kind.
var ErrUnknownCaveat = errors.New("unknown caveat")

// ErrEmptyChain is returned by CheckAll for a chain of zero grants.
// Checking every grant in an empty slice trivially succeeds — there is
// nothing to fail — which would make CheckAll(nil, req) grant any
// permission for any resource. The intersection-across-the-chain model has
// no defined meaning for zero links: there is no link whose permissions or
// resources ever named the request at all.
var ErrEmptyChain = errors.New("empty chain")

// clockSkewTolerance is applied symmetrically to every time-based check:
// ExpiresAt, NotBefore, ExpiresAfterFirstUse, and a Grant's own NotBefore
// and ExpiresAt. It tolerates this much disagreement between whichever
// clock set a bound and whichever clock produced Request.Now.
//
// The Biscuit spike found this to be the kind of thing a token format does
// not give you: tolerance has to live in one place or a consumer building
// its own check gets none. One place is here.
const clockSkewTolerance = 60 * time.Second

// Request carries the concrete facts of one access attempt that a token's
// caveats are checked against. A consumer builds one per request.
//
// Three fields are stateful counters rather than request facts:
// UsesBefore, FirstUsedAt and BytesTransferredBefore. A caveat that reads
// them never advances them. The caller owns reading the current counter,
// calling CheckAll inside the same database transaction as the operation,
// and persisting the advanced counter only after the operation succeeds.
// That ordering is what keeps a failed upload from silently consuming a use
// or a byte allowance — see
// TestStatefulCaveats_DoNotAdvanceWhenTheOperationFails.
//
// Whatever the caller keys those counters on, it MUST be the chain's
// domain.ChainID and never the presented token string. The presented bytes
// are not a unique identifier for a semantic token, and a byte-level
// permutation that still verifies would otherwise resubmit an
// already-redeemed token as if it were a different one. The ChainID is a
// claim inside the signed bytes, so there is nothing to canonicalize — see
// domain.RevocationID.
type Request struct {
	// Now is the instant the request is being evaluated at. CheckAll
	// refuses a zero value: the zero time is year 1, which would make an
	// expired grant pass. chain.Verifier.Verify ignores this field and uses
	// its own clock; use VerifyAt for an explicit instant. Direct CheckAll
	// callers must set it.
	Now time.Time
	// Permission is the single capability label being exercised.
	Permission domain.Permission
	// Resource is the node being acted on. An unvalidated path refuses
	// rather than being treated as "no resource, so no scope applies".
	Resource domain.ResourcePath
	// ClientIP is the request's source address, for ClientCIDR.
	ClientIP netip.Addr
	// ContentLength is the request body's length in bytes, or -1 when it
	// is unknown (a chunked request). Caveats that bound a length fail
	// closed on -1.
	ContentLength int64
	// ContentType is the SNIFFED type of the bytes on the wire, never a
	// caller-declared header — see AllowedContentTypes.
	ContentType string
	// ProcessorIdentity is the calling processor's opaque identity (a
	// certificate thumbprint, in CAS), for ProcessorAudience.
	ProcessorIdentity string
	// DeclaredDigest is the content address the uploader declared for this
	// upload, as an opaque string. Empty means none was declared.
	DeclaredDigest string
	// AuthenticatedRecipient reports whether the bearer presenting the
	// token is itself an authenticated principal rather than an anonymous
	// holder of a signed link.
	AuthenticatedRecipient bool
	// Readiness is the target's current readiness state, as an opaque
	// label. Empty is "unpopulated" and satisfies no RequiredReadiness.
	Readiness string
	// Rendition is the opaque label of the variant being served, for
	// Watermark. Empty means the original.
	Rendition string
	// ChainDepth is the TOTAL number of links in the chain the token was
	// presented as, the root included. A token that has never been derived
	// has ChainDepth == 1, not 0. DelegationDepth(n) is therefore a bound
	// on total chain length, allowing up to n-1 derivations beyond the
	// root.
	//
	// A caller does not populate this: chain.Verify fills it in from the
	// chain it has just walked, which closes the off-by-one that cas's
	// equivalent field invited. DelegationDepth still refuses a
	// ChainDepth below 1, so a Request assembled by hand fails closed
	// instead of satisfying every depth bound.
	ChainDepth int
	// UsesBefore is how many times this chain has already been redeemed,
	// before this request, for MaxUses.
	UsesBefore int
	// FirstUsedAt is when this chain was first redeemed, or the zero Time
	// if this request would be the first use, for ExpiresAfterFirstUse.
	FirstUsedAt time.Time
	// BytesTransferredBefore is how many bytes have already been served
	// under this chain, before this request, for MaxBytesTransferred. It
	// must be the bytes actually served, not the length each prior request
	// declared, so a transfer cut short is not overcounted.
	BytesTransferredBefore int64
}

// Caveat is a narrowing condition carried by one link of a chain. Every
// caveat a client can present must be of a kind this build recognizes:
// decoding and CheckAll both refuse any kind they do not, because a
// verifier that silently ignores a caveat it does not understand is a
// bypass, not a safe default.
type Caveat interface {
	// Kind returns the caveat's registered type name. It is both the wire
	// discriminator and the key that matches a child caveat against its
	// parent's counterpart during subsumption checking.
	Kind() string
	// Check reports whether req satisfies this caveat. A non-nil error
	// never names which caveat failed, and never includes any value
	// carried by the caveat or the request — see ErrCaveatNotSatisfied.
	Check(req Request) error
	// Narrows reports whether the receiver is at least as restrictive as
	// parent in every dimension it governs. It returns false when parent
	// is not the same concrete type, since nothing can be proven about a
	// comparison across kinds.
	//
	// Unlike cas, where Narrows was a mint-time courtesy the minter had to
	// remember to call, this is consulted on every verification: chain
	// verification refuses any link that does not narrow its parent. See
	// chain.Verify.
	Narrows(parent Caveat) bool
}

// encodableCaveat is implemented by every concrete caveat type here so the
// codec can serialize one into a token's claims without knowing its
// concrete type. It is deliberately separate from the public Caveat
// contract: Caveat describes verification behaviour that any package
// implementing a custom caveat must provide, while encodeValue describes
// this module's own canonical wire representation, which is published and
// therefore not open for a consumer to extend.
type encodableCaveat interface {
	Caveat
	encodeValue() (any, error)
}

// Decoder reconstructs a caveat from the JSON value its canonical wire form
// carries. schema is the consumer's declared resource hierarchy, needed by
// any caveat whose value contains a resource path; a decoder that does not
// need it ignores it.
type Decoder func(value []byte, schema domain.ResourceSchema) (Caveat, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Decoder{}
)

// registerCaveat makes decode the wire decoder for caveats of the given
// kind, so a token carrying one can be reconstructed. The sixteen kinds
// this package defines register themselves. Registering the same kind twice
// overwrites the previous decoder; kinds must be globally unique.
//
// The registry is global, as cas's was, because a caveat kind is part of
// the published wire format rather than a per-instance configuration: two
// builds that disagree about what "max_uses" decodes to do not
// interoperate, and that is a property of the format, not of a Verifier.
// The consumer's resource schema, which genuinely is per-instance, is
// passed to the decoder instead of being registered.
func registerCaveat(kind string, decode Decoder) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[kind] = decode
}

// DecodeCaveat looks up kind in the registry and decodes value, or returns
// ErrUnknownCaveat if the kind is not registered. This is the single
// fail-closed gate every caveat passes through when a token is parsed.
func DecodeCaveat(kind string, value []byte, schema domain.ResourceSchema) (Caveat, error) {
	registryMu.RLock()
	decode, ok := registry[kind]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unregistered kind", ErrUnknownCaveat)
	}
	if !utf8.Valid(value) {
		return nil, fmt.Errorf("%w: malformed value", ErrUnknownCaveat)
	}
	c, err := decode(value, schema)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed value", ErrUnknownCaveat)
	}
	if c == nil {
		// A decoder returning (nil, nil) would otherwise put a nil Caveat
		// into a grant, and calling Kind() on a nil interface value
		// panics: there is no concrete type to dispatch to.
		return nil, fmt.Errorf("%w: decoder returned nil", ErrUnknownCaveat)
	}
	canonical, cerr := Encode(c)
	if cerr != nil || canonical.Kind != kind || !bytes.Equal(canonical.Value, value) {
		return nil, fmt.Errorf("%w: caveat value is not canonical", ErrUnknownCaveat)
	}
	return c, nil
}

// IsRegisteredKind reports whether kind has a decoder registered.
func IsRegisteredKind(kind string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[kind]
	return ok
}

// RegisteredKinds returns every registered kind, sorted. It exists so a
// test can assert that the vocabulary is exactly the published one, and so
// a consumer can report what its build understands.
func RegisteredKinds() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(registry))
	for kind := range registry {
		out = append(out, kind)
	}
	slices.Sort(out)
	return out
}

// statefulKinds is the closed set of caveat kinds that cannot be checked
// from the request alone: each reads a counter that only the issuer holds,
// inside the operation's own transaction.
//
// It is the partition the envelope's token types rest on. A stateful caveat
// may appear only on a redemption token, whose audience is the issuer's own
// reservation service — so a third-party verifier refuses it on the "aud"
// claim alone, without needing to know that stateful caveats exist. See
// docs/wire-format.md.
var statefulKinds = map[string]struct{}{
	kindMaxUses:              {},
	kindExpiresAfterFirstUse: {},
	kindMaxBytesTransferred:  {},
}

// standardClaimKinds is the closed set of caveat kinds that are carried as
// a STANDARD JWT CLAIM — exp, nbf, prm, res — rather than as an entry in a
// token's "cav" array.
//
// That placement is the partition's point: a third-party verifier using a
// stock JWT library checks exp, nbf and audience because its library does,
// so the four dimensions that matter most are never in a field such a
// verifier would skip. It follows that the same kind must NOT also be
// expressible as a cav entry — docs/wire-format.md says a verifier MUST
// refuse one that appears there — because a token carrying expires_at in
// both places says one thing to a reader of the claims and another to a
// reader of the caveat array, and the two need not agree.
//
// The types themselves stay in the vocabulary and keep their codec: a
// Grant's own NotBefore, ExpiresAt, Permissions and Resources are compared
// through exactly those four Caveat implementations, so the ordering has
// one implementation rather than two. What is refused is only their
// appearance in cav, and that is enforced where the cav claim lives — see
// chain.grantFrom and chain.buildClaims.
var standardClaimKinds = map[string]struct{}{
	kindExpiresAt:     {},
	kindNotBefore:     {},
	kindPermissionSet: {},
	kindResourceScope: {},
}

// HasStandardClaim reports whether kind is carried as a standard JWT claim
// rather than as an entry in a token's "cav" array.
func HasStandardClaim(kind string) bool {
	_, ok := standardClaimKinds[kind]
	return ok
}

// StandardClaimKinds returns the kinds carried as standard claims, sorted.
func StandardClaimKinds() []string {
	out := make([]string, 0, len(standardClaimKinds))
	for kind := range standardClaimKinds {
		out = append(out, kind)
	}
	slices.Sort(out)
	return out
}

// IsStatefulKind reports whether kind requires a server-side reservation.
func IsStatefulKind(kind string) bool {
	_, ok := statefulKinds[kind]
	return ok
}

// StatefulKinds returns the stateful kinds, sorted.
func StatefulKinds() []string {
	out := make([]string, 0, len(statefulKinds))
	for kind := range statefulKinds {
		out = append(out, kind)
	}
	slices.Sort(out)
	return out
}

// Grant is one link's complete narrowing content: who it was minted for,
// what it permits, over what, when, and the caveats that narrow it
// further.
//
// The four fields beside Caveats are the ones carried as standard JWT
// claims — nbf, exp, prm and res — rather than as entries in the token's
// caveat array. That placement is the whole point of the partition: a
// third-party verifier using a stock JWT library checks exp, nbf and
// audience because its library does, and checks the grant because the
// published format tells it to, so the dimensions that matter most are
// never in a field such a verifier would skip.
type Grant struct {
	// Subject is who the link was minted for, opaque to this module.
	Subject domain.Subject
	// Permissions is what the link grants. An EMPTY set is never
	// "unrestricted": it means this link grants nothing and contributes an
	// empty set to the chain's intersection.
	Permissions domain.PermissionSet
	// Resources is the set of scopes the link covers, union semantics: a
	// request is in scope if at least one of them contains it. An EMPTY
	// list, like an empty permission set, puts nothing in scope.
	Resources []domain.ResourcePath
	// NotBefore and ExpiresAt bound the link's validity. A zero value
	// means that bound is simply not set, consistent with the dedicated
	// NotBefore and ExpiresAt caveats, and the same clockSkewTolerance
	// applies.
	NotBefore time.Time
	ExpiresAt time.Time
	// Caveats narrow the link further.
	Caveats []Caveat
}

// NarrowsPermissions reports whether every permission in g is also in
// parent's. An empty g.Permissions trivially narrows (there is nothing to
// widen); an empty parent.Permissions can only be narrowed by another empty
// set.
func (g Grant) NarrowsPermissions(parent Grant) bool {
	return g.Permissions.IsSubsetOf(parent.Permissions)
}

// NarrowsResources reports whether every resource in g is contained by at
// least one resource in parent's. An empty g.Resources trivially narrows.
// A path that cannot be evaluated — the zero value — counts as NOT
// contained: mint time must refuse what it cannot verify, not assume it is
// safe.
func (g Grant) NarrowsResources(parent Grant) bool {
	for _, child := range g.Resources {
		contained := false
		for _, p := range parent.Resources {
			if ok, err := p.Contains(child); err == nil && ok {
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

// NarrowsWindow reports whether g's validity window sits inside parent's: a
// child may bring expiry earlier and push its start later, never the
// reverse. A zero bound on the child means it did not restate the parent's,
// which is a widening when the parent had one — so it is refused.
func (g Grant) NarrowsWindow(parent Grant) bool {
	if !parent.ExpiresAt.IsZero() {
		if g.ExpiresAt.IsZero() || g.ExpiresAt.After(parent.ExpiresAt) {
			return false
		}
	}
	if !parent.NotBefore.IsZero() {
		if g.NotBefore.IsZero() || g.NotBefore.Before(parent.NotBefore) {
			return false
		}
	}
	return true
}

// NarrowsCaveats reports whether g restates every caveat kind parent
// carries, with a value at least as restrictive, and adds no caveat of a
// kind this build does not recognize.
//
// Restating is required rather than optional, and that is the rule that
// makes dropping a caveat a refusal rather than an attenuation. A child
// that simply omits its parent's MaxContentLength would otherwise be a
// token with no length bound derived from one that had a bound — a
// widening, by removal.
//
// Requiring it also makes each link's own caveat set the chain's effective
// set, which is what lets a verifier read the leaf and be right. It is not
// what verification relies on, though: CheckAll still intersects every
// link, so a widening child that somehow got signed is refused twice over.
func (g Grant) NarrowsCaveats(parent Grant) bool {
	for _, p := range parent.Caveats {
		if p == nil {
			return false
		}
		matched := false
		for _, c := range g.Caveats {
			if c == nil || c.Kind() != p.Kind() {
				continue
			}
			if c.Narrows(p) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, c := range g.Caveats {
		if c == nil || !IsRegisteredKind(c.Kind()) {
			return false
		}
	}
	return true
}

// Narrows reports whether g is at least as restrictive as parent in every
// dimension this module orders: its permissions, its resources, its
// validity window and its caveats.
//
// Subject is deliberately not among them. A subject is an opaque id, and
// this module cannot rank two of them — delegating to another holder is
// what a delegation token is for, and a chain preserves every link's
// subject, so a consumer that wants to police them can.
func (g Grant) Narrows(parent Grant) bool {
	return g.NarrowsPermissions(parent) &&
		g.NarrowsResources(parent) &&
		g.NarrowsWindow(parent) &&
		g.NarrowsCaveats(parent)
}

// CheckAll checks req against every grant in the chain — the intersection
// across the whole chain, all of which must pass. For each grant this
// enforces:
//
//   - the grant's own validity window, permission membership and resource
//     containment (checkGrantFields). These are not caveats, but nothing
//     else enforces them: signature verification checks signatures, and
//     the per-caveat loop never looks at them.
//   - every caveat the grant carries, with each kind re-checked against
//     the registry rather than trusting that it already decoded through
//     it. For a chain a verifier returned that is already true; any other
//     path that assembles a Grant in memory — a test, a future caller —
//     gets the same fail-closed guarantee.
//
// An empty chain refuses outright rather than vacuously passing. See
// ErrEmptyChain. A zero req.Now also refuses: the zero time is year 1,
// which would make an expired grant look valid.
func CheckAll(chain []Grant, req Request) error {
	if len(chain) == 0 {
		return ErrEmptyChain
	}
	if req.Now.IsZero() {
		// A zero time is year 1, which makes an expired grant look valid.
		// Refuse instead of guessing a clock: only the verifier owns "now".
		return ErrCaveatNotSatisfied
	}
	for _, g := range chain {
		if err := checkGrantFields(g, req); err != nil {
			return err
		}
		for _, c := range g.Caveats {
			if c == nil {
				return fmt.Errorf("%w: nil caveat", ErrUnknownCaveat)
			}
			if !IsRegisteredKind(c.Kind()) {
				return fmt.Errorf("%w: unregistered kind", ErrUnknownCaveat)
			}
			if err := c.Check(req); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkGrantFields enforces g's own validity window, permission grant and
// resource scope. A zero NotBefore or ExpiresAt means that bound is not
// set; an EMPTY Permissions or Resources, by contrast, is never
// "unrestricted" — it means this link grants nothing and no resource is in
// scope, which is what the capability ceiling being the intersection of the
// chain requires.
func checkGrantFields(g Grant, req Request) error {
	if !g.NotBefore.IsZero() && req.Now.Before(g.NotBefore.Add(-clockSkewTolerance)) {
		return ErrCaveatNotSatisfied
	}
	if !g.ExpiresAt.IsZero() && req.Now.After(g.ExpiresAt.Add(clockSkewTolerance)) {
		return ErrCaveatNotSatisfied
	}
	if !g.Permissions.Contains(req.Permission) {
		return ErrCaveatNotSatisfied
	}
	inScope := false
	for _, res := range g.Resources {
		if contains, err := res.Contains(req.Resource); err == nil && contains {
			inScope = true
			break
		}
	}
	if !inScope {
		return ErrCaveatNotSatisfied
	}
	return nil
}
