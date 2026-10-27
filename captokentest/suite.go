// Package captokentest is the conformance suite for the captoken module.
//
// RunCapabilitySuite, not captoken's interfaces, is the authoritative
// description of the contract's edge-case behaviour, and CHARTER.md counts
// a consumer as having ADOPTED this module when this suite runs green in
// that consumer's CI against that consumer's own wiring — its own resource
// schema, its own reservation and revocation adapters. That is what makes
// "adopted" testable rather than asserted.
//
// It is a sibling package rather than a suite.go inside the production
// package, and rather than a _test.go file, because both alternatives fail
// a requirement:
//
//   - Identifiers declared in a _test.go file are not importable from
//     outside that package, and this suite must be callable from another
//     module entirely.
//   - A non-test file that imports testing makes testing a dependency of
//     the production package, so every consumer's binary links it and
//     inherits its flag registrations. Keeping the suite here keeps testing
//     out of the production import graph.
//
// This is the standard library's own shape: net/http/httptest is a sibling
// of net/http, and testing/fstest.TestFS verifies any fs.FS.
//
// Every security invariant has its own named subtest, so an adapter is
// forced to exercise it rather than inheriting it by accident.
package captokentest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/laenenai/captoken"
)

// Wiring is what a consumer supplies to RunCapabilitySuite: its own
// declared resource schema, and its own adapters for the stateful subset.
//
// The schema is the consumer's real one, not a toy, which is the point:
// the suite exercises minting, derivation and verification over the
// hierarchy the consumer will actually use, so a hierarchy whose
// containment behaves unexpectedly fails here rather than in production.
type Wiring struct {
	// Schema is the consumer's declared resource hierarchy.
	Schema captoken.ResourceSchema
	// Outer and Inner are two paths in that schema where Outer strictly
	// CONTAINS Inner — a fileset and a document inside it, say. The suite
	// derives a narrower token from Outer to Inner and attacks the
	// reverse.
	Outer captoken.ResourcePath
	Inner captoken.ResourcePath
	// Sibling is a path that Outer does NOT contain. A sibling whose
	// identifier shares a prefix with one of Inner's is the most useful
	// value here, since that is the case a flattened scope string gets
	// wrong.
	Sibling captoken.ResourcePath
	// Wide and Narrow are two permission sets with Narrow a strict subset
	// of Wide, and Exercised is a member of Narrow.
	Wide      captoken.PermissionSet
	Narrow    captoken.PermissionSet
	Exercised captoken.Permission

	// Facts are the consumer's own labels for the request facts six of the
	// sixteen caveat kinds are checked against. Every field is optional and
	// defaults to a value of the suite's own; see RequestFacts for why
	// supplying the real ones makes the run stronger.
	Facts RequestFacts

	// Counters, Revocations and Nonces are the consumer's adapters. Any
	// may be nil, in which case the subtests that need it skip — but a
	// consumer that intends to use the stateful caveats must supply
	// Counters, and a consumer that intends to revoke must supply
	// Revocations.
	Counters    captoken.Counters
	Revocations captoken.Revocations
	Nonces      captoken.Nonces
}

// RequestFacts are the per-request facts a consumer's own pipeline
// populates, and which six caveat kinds are checked against:
// allowed_content_types, required_readiness, watermark,
// processor_audience, require_declared_digest and
// require_authenticated_recipient.
//
// Every field is optional. An empty one gets a label of the suite's own, so
// a consumer that supplies none still exercises all sixteen kinds — the
// caveat compares the token's label against the request's and both are then
// the suite's. What a consumer gains by supplying its real values is that
// the labels crossing its own pipeline are the ones the suite mints into a
// token and checks a request against, so a vocabulary whose values do not
// survive that round trip (a readiness state its own code spells
// differently in two places, a rendition label with a character its storage
// layer rewrites) fails here rather than in production.
//
// Two facts are deliberately NOT here. ContentLength and ClientIP are not a
// consumer's vocabulary — a length is a number and an address is an
// address — so the suite owns both, including the unset and unknown values
// the fail-closed rules are about.
type RequestFacts struct {
	// ContentType is the SNIFFED type of a request body the consumer
	// serves — never a declared header. See captoken.AllowedContentTypes.
	ContentType string
	// Readiness is a readiness state of the consumer's own, in the spelling
	// its own code uses. It is a server-supplied fact: nothing in a token
	// establishes it.
	Readiness string
	// Rendition is the label of one variant the consumer serves. The empty
	// label means the original, so this must name a real variant.
	Rendition string
	// ProcessorIdentity is a processor's opaque identity, as the consumer
	// spells one — a certificate thumbprint, in CAS.
	ProcessorIdentity string
	// DeclaredDigest is a content address an uploader declares, as the
	// consumer spells one.
	DeclaredDigest string
}

// withDefaults fills the facts a consumer left empty.
func (f RequestFacts) withDefaults() RequestFacts {
	if f.ContentType == "" {
		f.ContentType = "application/pdf"
	}
	if f.Readiness == "" {
		f.Readiness = "ready"
	}
	if f.Rendition == "" {
		f.Rendition = "captokentest.rendition"
	}
	if f.ProcessorIdentity == "" {
		f.ProcessorIdentity = "captokentest.processor"
	}
	if f.DeclaredDigest == "" {
		f.DeclaredDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return f
}

// suiteClock is the instant every subtest evaluates at. A fixed clock
// rather than time.Now so that a failure is reproducible and a
// clock-tolerance boundary is exact.
var suiteClock = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

const (
	suiteIssuer   = "captokentest.issuer"
	suiteGateway  = "captokentest.gateway"
	suiteReserver = "captokentest.reservations"
)

// suiteClientIP is the address every request is made from, and
// suiteClientPrefix the masked prefix that contains it — the suite owns
// both, because an address is not part of a consumer's vocabulary. A /24
// rather than a /32 so that ClientCIDR is exercised as a range test rather
// than as an equality one.
var (
	suiteClientIP     = netip.MustParseAddr("10.1.2.3")
	suiteClientPrefix = netip.MustParsePrefix("10.1.2.0/24")
	suiteForeignIP    = netip.MustParseAddr("10.9.9.9")
)

// RunCapabilitySuite runs the contract every captoken deployment must
// satisfy. newWiring is called once per subtest, receiving that subtest's
// own *T, so an adapter that needs per-test setup and teardown (a scratch
// schema, a transaction that rolls back, a container it starts) registers
// it with t.Cleanup inside newWiring and every subtest gets fresh,
// isolated state.
func RunCapabilitySuite(t *testing.T, newWiring func(t *testing.T) Wiring) {
	t.Helper()

	subtests := map[string]func(t *testing.T, w Wiring, h *harness){
		"MintVerifyRoundTrip":                     testMintVerifyRoundTrip,
		"DeriveNarrowsOfflineWithoutTheIssuer":    testDeriveOffline,
		"NoDerivationCanWidenItsAncestor":         testNoDerivationCanWiden,
		"ATruncatedChainAuthorisesNothing":        testTruncationAuthorisesNothing,
		"AForeignRootKeyIsRefused":                testForeignRootKey,
		"AnUnknownResourceIsOutOfScope":           testSiblingResourceOutOfScope,
		"ARefusalNamesNothing":                    testRefusalNamesNothing,
		"StatefulCaveatsRequireAReservation":      testStatefulRequiresReservation,
		"StatefulCaveatsDoNotAdvanceOnFailure":    testStatefulDoesNotAdvance,
		"RevokingTheAncestorKillsEveryDescendant": testRevocationIsChainWide,
		"ASingleUseNonceIsConsumedOnlyOnce":       testNonceConsumedOnce,

		// The presentation: the chain as a string. See presentation.go.
		"ADerivedChainVerifiesToDepthThree":   testDepthThree,
		"AReorderedChainIsRefused":            testReorderedChain,
		"ADroppedOrRepeatedLinkIsRefused":     testDroppedOrRepeatedLink,
		"ALinkFromAnotherChainIsRefused":      testSplicedLink,
		"AMalformedPresentationIsRefused":     testMalformedPresentation,
		"EveryTruncationOfAChainIsRefused":    testTruncatedPresentation,
		"ASingleAlteredByteAnywhereIsRefused": testAlteredByte,

		// The caveat vocabulary: all sixteen kinds. See caveats.go.
		"EveryCaveatKindIsChecked":            testEveryCaveatKindIsChecked,
		"EveryStandardClaimIsChecked":         testEveryStandardClaimIsChecked,
		"EveryRegisteredKindIsExercised":      testEveryRegisteredKindHasARow,
		"EveryKindOrdersItsOwnValues":         testEveryKindOrdersItsOwnValues,
		"NoCaveatKindNarrowsAnother":          testNoKindNarrowsAnother,
		"StatefulCaveatsEnforceTheirBounds":   testStatefulCaveatsEnforceTheirBounds,
		"CountersDoNotLoseConcurrentAdvances": testCountersDoNotLoseConcurrentAdvances,
	}

	for name, run := range subtests {
		t.Run(name, func(t *testing.T) {
			w := newWiring(t)
			validateWiring(t, w)
			run(t, w, newHarness(t, w))
		})
	}
}

// validateWiring fails the subtest if the consumer's wiring does not
// satisfy the relationships the suite's cases are written against. A
// confusing failure deep inside a case is worse than a clear one here.
func validateWiring(t *testing.T, w Wiring) {
	t.Helper()

	if w.Schema.IsZero() {
		t.Fatal("Wiring.Schema is the zero ResourceSchema")
	}
	if contains, err := w.Outer.Contains(w.Inner); err != nil || !contains {
		t.Fatalf("Wiring.Outer must strictly contain Wiring.Inner: Contains = (%v, %v)", contains, err)
	}
	if contains, err := w.Inner.Contains(w.Outer); err != nil || contains {
		t.Fatalf("Wiring.Inner must not contain Wiring.Outer: Contains = (%v, %v)", contains, err)
	}
	if contains, err := w.Outer.Contains(w.Sibling); err != nil || contains {
		t.Fatalf("Wiring.Outer must not contain Wiring.Sibling: Contains = (%v, %v)", contains, err)
	}
	if !w.Narrow.IsSubsetOf(w.Wide) || w.Wide.IsSubsetOf(w.Narrow) {
		t.Fatal("Wiring.Narrow must be a strict subset of Wiring.Wide")
	}
	if !w.Narrow.Contains(w.Exercised) {
		t.Fatal("Wiring.Exercised must be a member of Wiring.Narrow")
	}
}

// harness is the minter, deriver and verifiers one subtest works with.
type harness struct {
	rootPub  ed25519.PublicKey
	minter   *captoken.Minter
	deriver  *captoken.Deriver
	gateway  *captoken.Verifier
	reserver *captoken.Verifier
	clock    *captoken.FixedClock
}

func newHarness(t *testing.T, w Wiring) *harness {
	t.Helper()
	clock := captoken.NewFixedClock(suiteClock)

	key, err := captoken.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	minter, err := captoken.NewMinter(captoken.MinterConfig{
		Issuer: suiteIssuer, RootKey: key.Private, Schema: w.Schema, Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}
	deriver, err := captoken.NewDeriver(captoken.DeriverConfig{Schema: w.Schema, Clock: clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}

	verifier := func(audience captoken.Audience) *captoken.Verifier {
		v, verr := captoken.NewVerifier(captoken.VerifierConfig{
			Issuer:       suiteIssuer,
			RootKeys:     []ed25519.PublicKey{key.Public},
			Audience:     audience,
			Schema:       w.Schema,
			Clock:        clock,
			Reservations: w.Counters,
			Revocations:  w.Revocations,
		})
		if verr != nil {
			t.Fatalf("NewVerifier(%q) error = %v", audience, verr)
		}
		return v
	}

	return &harness{
		rootPub: key.Public, minter: minter, deriver: deriver,
		gateway: verifier(suiteGateway), reserver: verifier(suiteReserver), clock: clock,
	}
}

// rootSpec is a wide delegation token over Outer. Its audience lists both
// the gateway and the reservation service, because a delegation token's
// audience is the set its descendants may draw from.
func (h *harness) rootSpec(w Wiring) captoken.MintSpec {
	return captoken.MintSpec{
		Type:        captoken.TypeDelegation,
		Subject:     "holder-1",
		Audience:    []captoken.Audience{suiteGateway, suiteReserver},
		ExpiresAt:   suiteClock.Add(24 * time.Hour),
		Permissions: w.Wide,
		Resources:   []captoken.ResourcePath{w.Outer},
		Caveats:     []captoken.Caveat{captoken.MaxContentLength(1 << 20)},
	}
}

// middleSpec is a delegation token narrower than the root: Narrow
// permissions over Inner. Widening attacks are derived from it, because a
// derivation from the ROOT that asks for the root's own grant is not a
// widening at all.
func (h *harness) middleSpec(w Wiring) captoken.MintSpec {
	return captoken.MintSpec{
		Type:        captoken.TypeDelegation,
		Subject:     "holder-2",
		Audience:    []captoken.Audience{suiteGateway},
		ExpiresAt:   suiteClock.Add(2 * time.Hour),
		Permissions: w.Narrow,
		Resources:   []captoken.ResourcePath{w.Inner},
		Caveats:     []captoken.Caveat{captoken.MaxContentLength(1 << 12)},
	}
}

// leafSpec is a narrower execution token over Inner.
func (h *harness) leafSpec(w Wiring) captoken.MintSpec {
	return captoken.MintSpec{
		Type:        captoken.TypeExecution,
		Subject:     "holder-2",
		Audience:    []captoken.Audience{suiteGateway},
		ExpiresAt:   suiteClock.Add(time.Hour),
		Permissions: w.Narrow,
		Resources:   []captoken.ResourcePath{w.Inner},
		Caveats:     []captoken.Caveat{captoken.MaxContentLength(1 << 10)},
	}
}

// request is the access attempt every subtest evaluates, and it satisfies
// every caveat kind the suite mints with the matching value — so a subtest
// that wants a refusal says which single fact it is changing, and a reader
// can see what the refusal is attributable to.
//
// AuthenticatedRecipient is true here because that is the satisfying case;
// the anonymous bearer is one of the fail-closed gates and sets it back to
// false explicitly.
func (h *harness) request(w Wiring) captoken.Request {
	f := w.Facts.withDefaults()
	return captoken.Request{
		Now:                    suiteClock,
		Permission:             w.Exercised,
		Resource:               w.Inner,
		ClientIP:               suiteClientIP,
		ContentLength:          512,
		ContentType:            f.ContentType,
		ProcessorIdentity:      f.ProcessorIdentity,
		DeclaredDigest:         f.DeclaredDigest,
		AuthenticatedRecipient: true,
		Readiness:              f.Readiness,
		Rendition:              f.Rendition,
	}
}

// chain mints a root and derives the leaf from it, returning the
// presentation and the root's holder key.
func (h *harness) chain(t *testing.T, w Wiring) (string, ed25519.PrivateKey) {
	t.Helper()
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	leaf, err := h.deriver.Derive(root.Token, root.HolderKey, h.leafSpec(w))
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}
	return leaf.Token, root.HolderKey
}

// chainOfThree mints root(delegation) -> middle(delegation) -> leaf(execution)
// and returns the leaf's presentation together with the holder key of each
// delegation link, root first.
//
// Three links rather than two because that is the shortest chain with an
// INTERIOR link, and an interior link is the position a reordering, a drop
// and a splice all act on — a two-link chain has nowhere to move anything
// to. Every link narrows its parent, so the chain is honest and the attacks
// over it are attacking something.
func (h *harness) chainOfThree(t *testing.T, w Wiring) (string, []ed25519.PrivateKey) {
	t.Helper()
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	middle, err := h.deriver.Derive(root.Token, root.HolderKey, h.middleSpec(w))
	if err != nil {
		t.Fatalf("Derive(the middle link) error = %v", err)
	}
	leaf, err := h.deriver.Derive(middle.Token, middle.HolderKey, h.leafSpec(w))
	if err != nil {
		t.Fatalf("Derive(the leaf) error = %v", err)
	}
	return leaf.Token, []ed25519.PrivateKey{root.HolderKey, middle.HolderKey}
}

// ---- the cases -----------------------------------------------------------

func testMintVerifyRoundTrip(t *testing.T, w Wiring, h *harness) {
	minted, err := h.minter.Mint(h.leafSpec(w))
	if err != nil {
		t.Fatalf("Mint(an execution token) error = %v", err)
	}
	if minted.HolderKey != nil {
		t.Error("a terminal token returned a holder key; it cannot be derived from, so there is no key to hold")
	}

	verified, err := h.gateway.Verify(context.Background(), minted.Token, h.request(w))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if verified.Type != captoken.TypeExecution {
		t.Errorf("Type = %q, want %q", verified.Type, captoken.TypeExecution)
	}
	if verified.Depth != 1 {
		t.Errorf("Depth = %d, want 1", verified.Depth)
	}
	if !verified.Permissions.Contains(w.Exercised) {
		t.Errorf("Permissions = %v, want it to contain %q", verified.Permissions.Sorted(), w.Exercised)
	}
	if verified.ChainID == "" {
		t.Error("ChainID is empty; it is the chain's revocation key")
	}
}

func testDeriveOffline(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chain(t, w)

	verified, err := h.gateway.Verify(context.Background(), presented, h.request(w))
	if err != nil {
		t.Fatalf("Verify(a derived chain) error = %v, want nil", err)
	}
	if verified.Depth != 2 {
		t.Errorf("Depth = %d, want 2", verified.Depth)
	}
	// The effective grant is the intersection, which is the narrower link's
	// here because every link narrowed.
	if w.Wide.IsSubsetOf(verified.Permissions) {
		t.Error("the effective permission set is as wide as the root's; a derivation must narrow it")
	}
}

// testNoDerivationCanWiden is the module's central invariant, exercised
// against the consumer's own schema and permission vocabulary. Every
// dimension is attacked.
func testNoDerivationCanWiden(t *testing.T, w Wiring, h *harness) {
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	middle, err := h.deriver.Derive(root.Token, root.HolderKey, h.middleSpec(w))
	if err != nil {
		t.Fatalf("Derive(the middle link) error = %v", err)
	}

	cases := map[string]func(s *captoken.MintSpec){
		"a permission the parent never granted": func(s *captoken.MintSpec) { s.Permissions = w.Wide },
		"a resource outside the parent's scope": func(s *captoken.MintSpec) {
			s.Resources = []captoken.ResourcePath{w.Sibling}
		},
		"a later expiry": func(s *captoken.MintSpec) { s.ExpiresAt = suiteClock.Add(72 * time.Hour) },
		"a raised ceiling": func(s *captoken.MintSpec) {
			s.Caveats = []captoken.Caveat{captoken.MaxContentLength(1 << 30)}
		},
		"a dropped caveat": func(s *captoken.MintSpec) { s.Caveats = nil },
		"a widened audience": func(s *captoken.MintSpec) {
			s.Audience = []captoken.Audience{suiteGateway, "somewhere-else"}
		},
		"an unvalidated resource path": func(s *captoken.MintSpec) {
			s.Resources = []captoken.ResourcePath{{}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := h.leafSpec(w)
			mutate(&spec)
			if _, err := h.deriver.Derive(middle.Token, middle.HolderKey, spec); !errors.Is(err, captoken.ErrInvalidToken) {
				t.Errorf("Derive(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}

	// Widening the ROOT's own permission set is not a derivation at all —
	// a root has no parent — so the check that matters is that the chain's
	// authority is the intersection, which the case above covers. What
	// must also hold is that a chain cannot be extended past a terminal
	// link, which is the other half of why truncation is powerless.
	presented, _ := h.chain(t, w)
	if _, err := h.deriver.Derive(presented, root.HolderKey, h.leafSpec(w)); !errors.Is(err, captoken.ErrInvalidToken) {
		t.Errorf("Derive(from a terminal link) error = %v, want wrapping ErrInvalidToken", err)
	}
}

// testTruncationAuthorisesNothing is the property that replaces cas's seal
// and proof: every proper prefix of a chain ends in a delegation token, and
// a delegation token authorises no operation.
func testTruncationAuthorisesNothing(t *testing.T, w Wiring, h *harness) {
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if _, err := h.deriver.Derive(root.Token, root.HolderKey, h.leafSpec(w)); err != nil {
		t.Fatalf("Derive() error = %v", err)
	}

	// The root alone: a delegation token, presented for an authorization
	// decision. It must be refused even though it is perfectly valid and
	// grants MORE than the leaf derived from it.
	_, err = h.gateway.Verify(context.Background(), root.Token, h.request(w))
	if !errors.Is(err, captoken.ErrInvalidToken) {
		t.Fatalf("Verify(a delegation token) error = %v, want wrapping ErrInvalidToken", err)
	}
	if !errors.Is(err, captoken.ErrNotAuthorizing) {
		t.Errorf("Verify(a delegation token) error = %v, want wrapping ErrNotAuthorizing", err)
	}
}

func testForeignRootKey(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chain(t, w)

	other, err := captoken.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	v, err := captoken.NewVerifier(captoken.VerifierConfig{
		Issuer: suiteIssuer, RootKeys: []ed25519.PublicKey{other.Public},
		Audience: suiteGateway, Schema: w.Schema, Clock: h.clock,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, err := v.Verify(context.Background(), presented, h.request(w)); !errors.Is(err, captoken.ErrInvalidToken) {
		t.Errorf("Verify(under a foreign root key) error = %v, want wrapping ErrInvalidToken", err)
	}
}

// testSiblingResourceOutOfScope is the consumer-schema half of the
// containment rule, and the case a flattened scope string gets wrong: a
// sibling whose identifier merely shares a prefix with one in scope is NOT
// in scope.
func testSiblingResourceOutOfScope(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chain(t, w)

	req := h.request(w)
	req.Resource = w.Sibling
	if _, err := h.gateway.Verify(context.Background(), presented, req); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
		t.Errorf("Verify(a request for a sibling resource) error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

// testRefusalNamesNothing is the error-discipline invariant. A verifier
// that explains why a request was refused hands an attacker a dimension to
// search along, so a refusal is the bare sentinel and nothing more.
func testRefusalNamesNothing(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chain(t, w)

	// Force the two refusal paths and require each to be exactly its
	// sentinel's text.
	req := h.request(w)
	req.Resource = w.Sibling
	if err := mustFail(t, h.gateway, presented, req); err.Error() != captoken.ErrCaveatNotSatisfied.Error() {
		t.Errorf("a request-level refusal said %q, want exactly %q",
			err.Error(), captoken.ErrCaveatNotSatisfied.Error())
	}

	if err := mustFail(t, h.gateway, presented+"tampered", h.request(w)); err.Error() != captoken.ErrInvalidToken.Error() {
		t.Errorf("a token-level refusal said %q, want exactly %q",
			err.Error(), captoken.ErrInvalidToken.Error())
	}
}

func mustFail(t *testing.T, v *captoken.Verifier, presented string, req captoken.Request) error {
	t.Helper()
	_, err := v.Verify(context.Background(), presented, req)
	if err == nil {
		t.Fatal("expected Verify() to refuse")
	}
	return err
}

// testStatefulRequiresReservation is the fail-closed outcome the charter's
// two-surface design rests on: a verifier that cannot supply the counters
// refuses rather than skipping the check, so the worst case of a partial
// verifier is a refused request and never an accepted one.
func testStatefulRequiresReservation(t *testing.T, w Wiring, h *harness) {
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	spec := h.leafSpec(w)
	spec.Type = captoken.TypeRedemption
	spec.Audience = []captoken.Audience{suiteReserver}
	spec.Caveats = append(spec.Caveats, captoken.MaxUses(2))
	redemption, err := h.deriver.Derive(root.Token, root.HolderKey, spec)
	if err != nil {
		t.Fatalf("Derive(a redemption token) error = %v", err)
	}

	// A third party — the gateway, whose audience is not the reservation
	// service — refuses it on the audience claim alone, without needing to
	// know that stateful caveats exist.
	if _, err := h.gateway.Verify(context.Background(), redemption.Token, h.request(w)); !errors.Is(err, captoken.ErrInvalidToken) {
		t.Errorf("a third party accepted a redemption token: error = %v, want wrapping ErrInvalidToken", err)
	}

	// A verifier that IS the audience but has no Counters refuses too.
	noCounters, err := captoken.NewVerifier(captoken.VerifierConfig{
		Issuer: suiteIssuer, RootKeys: []ed25519.PublicKey{h.rootPub},
		Audience: suiteReserver, Schema: w.Schema, Clock: h.clock,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, err := noCounters.Verify(context.Background(), redemption.Token, h.request(w)); !errors.Is(err, captoken.ErrNoReservationService) {
		t.Errorf("a verifier with no reservation service error = %v, want wrapping ErrNoReservationService", err)
	}

	// And a stateful caveat on an execution token is refused at mint.
	bad := h.leafSpec(w)
	bad.Caveats = append(bad.Caveats, captoken.MaxUses(1))
	if _, err := h.deriver.Derive(root.Token, root.HolderKey, bad); !errors.Is(err, captoken.ErrInvalidToken) {
		t.Errorf("Derive(a stateful caveat on an execution token) error = %v, want wrapping ErrInvalidToken", err)
	}

	if w.Counters == nil {
		t.Skip("Wiring.Counters is nil: a consumer that uses the stateful caveats must supply one")
	}
	if _, err := h.reserver.Verify(context.Background(), redemption.Token, h.request(w)); err != nil {
		t.Errorf("the reservation service refused a redemption token: %v", err)
	}
}

// testStatefulDoesNotAdvance is the ordering discipline, and it is the one
// invariant this module cannot enforce — it is a property of the caller's
// transaction. What it CAN enforce, and what this checks, is that
// verification only ever reads the counters, so a failed operation cannot
// consume a use or a byte allowance.
func testStatefulDoesNotAdvance(t *testing.T, w Wiring, h *harness) {
	if w.Counters == nil {
		t.Skip("Wiring.Counters is nil")
	}

	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	spec := h.leafSpec(w)
	spec.Type = captoken.TypeRedemption
	spec.Audience = []captoken.Audience{suiteReserver}
	spec.Caveats = append(spec.Caveats, captoken.MaxUses(1))
	redemption, err := h.deriver.Derive(root.Token, root.HolderKey, spec)
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}

	verified, err := h.reserver.Verify(context.Background(), redemption.Token, h.request(w))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	before, err := w.Counters.Read(context.Background(), verified.ChainID)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// Verify repeatedly. The counters must not move: the caller advances
	// them, after the operation succeeds, inside its own transaction.
	for range 5 {
		if _, err := h.reserver.Verify(context.Background(), redemption.Token, h.request(w)); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	}
	after, err := w.Counters.Read(context.Background(), verified.ChainID)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if after != before {
		t.Fatalf("verification advanced the counters from %+v to %+v; it must only read them", before, after)
	}

	// Once the caller records the one permitted use, the next request is
	// refused — and refused as a request the token does not permit, not as
	// an invalid token.
	if err := w.Counters.Advance(context.Background(), verified.ChainID, captoken.Advance{Uses: 1}); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	if _, err := h.reserver.Verify(context.Background(), redemption.Token, h.request(w)); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
		t.Errorf("Verify() after the single use was spent error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

// testRevocationIsChainWide pins the property the revocation identifier
// exists for: it is the root link's token id, carried verbatim by every
// descendant, so ONE record kills the chain with no enumeration of
// descendants.
func testRevocationIsChainWide(t *testing.T, w Wiring, h *harness) {
	if w.Revocations == nil {
		t.Skip("Wiring.Revocations is nil")
	}

	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	leaf, err := h.deriver.Derive(root.Token, root.HolderKey, h.leafSpec(w))
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}
	grandchildSpec := h.leafSpec(w)
	grandchildSpec.Type = captoken.TypeDelegation
	middle, err := h.deriver.Derive(root.Token, root.HolderKey, grandchildSpec)
	if err != nil {
		t.Fatalf("Derive(a second child) error = %v", err)
	}

	verified, err := h.gateway.Verify(context.Background(), leaf.Token, h.request(w))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	deep, err := h.deriver.Derive(middle.Token, middle.HolderKey, h.leafSpec(w))
	if err != nil {
		t.Fatalf("Derive(a grandchild) error = %v", err)
	}
	deepVerified, err := h.gateway.Verify(context.Background(), deep.Token, h.request(w))
	if err != nil {
		t.Fatalf("Verify(a grandchild) error = %v", err)
	}
	if deepVerified.ChainID != verified.ChainID {
		t.Fatalf("two descendants of one root report different chain ids (%q and %q); "+
			"revocation keys on the ancestor's identifier and must be byte-identical in every descendant",
			deepVerified.ChainID, verified.ChainID)
	}

	// One record.
	if err := w.Revocations.Revoke(context.Background(), verified.ChainID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	for name, token := range map[string]string{"the child": leaf.Token, "the grandchild": deep.Token} {
		if _, err := h.gateway.Verify(context.Background(), token, h.request(w)); !errors.Is(err, captoken.ErrRevoked) {
			t.Errorf("after revoking the ancestor, %s error = %v, want wrapping ErrRevoked", name, err)
		}
	}

	// Revocation is idempotent and has no undo.
	if err := w.Revocations.Revoke(context.Background(), verified.ChainID); err != nil {
		t.Errorf("Revoke() a second time error = %v, want nil (revocation is idempotent)", err)
	}
}

func testNonceConsumedOnce(t *testing.T, w Wiring, h *harness) {
	if w.Nonces == nil {
		t.Skip("Wiring.Nonces is nil")
	}

	minted, err := h.minter.Mint(h.leafSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	verified, err := h.gateway.Verify(context.Background(), minted.Token, h.request(w))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if err := w.Nonces.Consume(context.Background(), verified.ChainID, "operation-1"); err != nil {
		t.Fatalf("Consume() the first time error = %v, want nil", err)
	}
	if err := w.Nonces.Consume(context.Background(), verified.ChainID, "operation-1"); !errors.Is(err, captoken.ErrNonceConsumed) {
		t.Errorf("Consume() the second time error = %v, want wrapping ErrNonceConsumed", err)
	}
	// A different operation under the same chain is a different record: a
	// nonce records that one OPERATION happened, not that the chain was
	// redeemed.
	if err := w.Nonces.Consume(context.Background(), verified.ChainID, "operation-2"); err != nil {
		t.Errorf("Consume() a different nonce error = %v, want nil", err)
	}
}
