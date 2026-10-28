package captokentest

// This file holds the fail-closed gates: the cases where an implementation
// does not know enough to decide, and must therefore refuse.
//
// They matter more than anything else in this suite. Every other property
// here is about a refusal an implementation gets right by doing its job; a
// fail-closed gate is about what it does when a value is missing, a field was
// never populated, or a condition is one it does not understand — and the
// wrong answer in every one of those cases is to carry on and accept. Five
// of them were reachable only from inside captoken when CAS adopted the
// module, and the one that mattered most is the first below.
//
// # An unknown caveat kind, and why the fixture is built the way it is
//
// "A verifier meeting a caveat kind it does not understand must refuse" is
// the property that makes the vocabulary safe to extend at all. Without it,
// a consumer cannot detect an implementation that ignores what it does not
// recognize — and such an implementation silently widens EVERY token in the
// system, because every narrowing condition it has not implemented stops
// applying while the token still verifies.
//
// A consumer cannot provoke that through the port, and that is a finding
// about the API rather than a gap in the suite. Two deliberate closures
// stand in the way, and both are right:
//
//   - caveat registration is unexported, so a consumer cannot
//     add a kind, because a consumer that could would issue tokens no other
//     verifier understands;
//   - a Caveat implementation declared outside caveat cannot be
//     serialized at all, because the encode side of the vocabulary is an
//     unexported method, so a foreign caveat is refused at MINT rather than
//     written to the wire.
//
// Those two are themselves worth asserting, and the first two cases below
// do: a consumer's own Caveat is refused by CheckAll and refused by Mint.
// But neither is the property. The property is about a token that already
// exists and a verifier that cannot read all of it.
//
// So the fixture is built with a test-only kind that lives in
// caveat — see the reasoning at caveat.RegisterConformanceCaveat — and the
// sequence is: register the kind, mint a chain carrying it through the
// implementation's own Mint and Derive, check that the verifier ACCEPTS it,
// unregister the kind, and check that the same verifier now refuses the same
// bytes. The token is the implementation's own output, so nothing about the
// wire layout is assumed; the only thing that changed between the two
// verifications is what the build knows. That is exactly the scenario the
// rule exists for: an older verifier meeting a token a newer issuer minted.
//
// The alternative — a test-only exported constructor that let a consumer
// mint an arbitrary kind — was rejected. It would have put a crack in the
// closed vocabulary into the published surface in order to test that the
// vocabulary is closed.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/laenenai/captoken"
	"github.com/laenenai/captoken/caveat"
)

// foreignCaveat is a caveat of a kind no build registers, declared the way a
// consumer would declare one: a type of its own satisfying captoken.Caveat.
//
// Check returns nil and Narrows returns true, so every gate below that
// refuses it refuses it for the only reason left — that its kind is not one
// this build knows. A foreignCaveat that refused on its own would make these
// cases pass against an implementation that never consulted the registry.
type foreignCaveat struct{}

func (foreignCaveat) Kind() string                   { return "captokentest.not-a-registered-kind" }
func (foreignCaveat) Check(captoken.Request) error   { return nil }
func (foreignCaveat) Narrows(_ captoken.Caveat) bool { return true }

// testUnknownCaveatKindFailsClosed is the gate. See this file's header
// comment for why the third case is built the way it is.
func testUnknownCaveatKindFailsClosed(t *testing.T, w Wiring, h *harness) {
	ctx := context.Background()

	// The in-memory gate. CheckAll re-checks every kind against the
	// registry rather than trusting that a grant decoded through it, so any
	// path that assembles a chain in memory — a consumer evaluating a chain
	// it already holds — gets the same guarantee a presented token gets.
	t.Run("CheckAll refuses a kind it does not know", func(t *testing.T) {
		honest := h.grant(w)
		if err := captoken.CheckAll([]captoken.Grant{honest}, h.request(w)); err != nil {
			t.Fatalf("CheckAll(an honest grant) error = %v, want nil: the refusal below would otherwise "+
				"be attributable to the grant rather than to the unknown kind", err)
		}

		unknown := honest
		unknown.Caveats = append([]captoken.Caveat{foreignCaveat{}}, honest.Caveats...)
		if err := captoken.CheckAll([]captoken.Grant{unknown}, h.request(w)); !errors.Is(err, captoken.ErrUnknownCaveat) {
			t.Errorf("CheckAll(a grant carrying an unregistered kind) error = %v, want wrapping "+
				"ErrUnknownCaveat; a verifier that ignores a condition it does not understand is a bypass",
				err)
		}
	})

	// The mint gate: an unknown kind cannot be put on the wire in the first
	// place, which is why a consumer cannot build the fixture the third
	// case needs.
	t.Run("minting refuses a kind that has no canonical encoding", func(t *testing.T) {
		spec := h.leafSpec(w)
		spec.Caveats = append(spec.Caveats, foreignCaveat{})
		if _, err := h.minter.Mint(spec); !errors.Is(err, captoken.ErrInvalidToken) {
			t.Errorf("Mint(a caveat of a kind outside the vocabulary) error = %v, want wrapping "+
				"ErrInvalidToken", err)
		}
	})

	// The wire gate, and the property itself.
	t.Run("a verifier refuses a token carrying a kind it no longer knows", func(t *testing.T) {
		probe, unregister := caveat.RegisterConformanceCaveat()
		// The registry is process-global, so the probe must be gone by the
		// time the next subtest asks what this build understands — whatever
		// happens below, including a t.Fatal. Removing a kind twice is a
		// no-op, so the explicit removal further down is safe beside this.
		t.Cleanup(unregister)

		presented := h.chainCarrying(t, w, probe)

		// The control: while the build knows the kind, the chain verifies.
		// Without this the refusal below would prove only that the chain
		// was refused, not that it was refused for the kind.
		if _, err := h.gateway.Verify(ctx, presented, h.request(w)); err != nil {
			t.Fatalf("Verify(a chain carrying a kind this build knows) error = %v, want nil", err)
		}

		// Now the build does not know it. Nothing about the token changed.
		unregister()

		if _, err := h.gateway.Verify(ctx, presented, h.request(w)); !errors.Is(err, captoken.ErrInvalidToken) {
			t.Errorf("Verify(the same chain, after the build stopped knowing one of its caveat kinds) "+
				"error = %v, want wrapping ErrInvalidToken.\n"+
				"An implementation that accepts a caveat it cannot evaluate has silently widened every "+
				"token carrying one: the condition stops applying and the credential still verifies.", err)
		}

		// And the vocabulary is back to the published one. Asserted here
		// rather than left to whichever later subtest happens to notice:
		// the registry is process-global and the suite's subtests run in
		// map order, so a probe left behind would fail somewhere else,
		// sometimes, and point at the wrong case.
		if slices.Contains(captoken.RegisteredKinds(), caveat.ConformanceKind) {
			t.Fatalf("the conformance probe is still registered, so every later subtest now sees a "+
				"vocabulary of %d kinds", len(captoken.RegisteredKinds()))
		}
	})
}

// testAnEmptyChainAuthorisesNothing is the gate with the sharpest teeth,
// because the wrong answer is the one a loop produces by itself: checking
// every grant of an empty chain trivially succeeds, so CheckAll(nil, req)
// would grant every permission on every resource.
func testAnEmptyChainAuthorisesNothing(t *testing.T, w Wiring, h *harness) {
	req := h.request(w)
	for name, chain := range map[string][]captoken.Grant{
		"a nil chain":    nil,
		"an empty slice": {},
	} {
		if err := captoken.CheckAll(chain, req); !errors.Is(err, captoken.ErrEmptyChain) {
			t.Errorf("CheckAll(%s) error = %v, want wrapping ErrEmptyChain", name, err)
		}
	}
}

// testANilCaveatIsRefused is the gate that is also a crash: Kind() on a nil
// interface value has no concrete type to dispatch to and panics, so "refuse"
// and "do not take the process down" are the same requirement here.
func testANilCaveatIsRefused(t *testing.T, w Wiring, h *harness) {
	grant := h.grant(w)
	grant.Caveats = append([]captoken.Caveat{nil}, grant.Caveats...)
	if err := captoken.CheckAll([]captoken.Grant{grant}, h.request(w)); !errors.Is(err, captoken.ErrUnknownCaveat) {
		t.Errorf("CheckAll(a grant carrying a nil caveat) error = %v, want wrapping ErrUnknownCaveat", err)
	}

	spec := h.leafSpec(w)
	spec.Caveats = append(spec.Caveats, nil)
	if _, err := h.minter.Mint(spec); !errors.Is(err, captoken.ErrInvalidToken) {
		t.Errorf("Mint(a spec carrying a nil caveat) error = %v, want wrapping ErrInvalidToken", err)
	}
}

// testUnknownFactsFailClosed is the set of gates about a request fact that is
// missing rather than wrong. Each one is a field a caller could forget, and
// in every case the fail-closed direction is the opposite of the one a
// zero value suggests: an unknown length is not "no length to bound", an
// unresolved path is not "no resource, so no scope applies", and an unset
// address is not "every address".
func testUnknownFactsFailClosed(t *testing.T, w Wiring, h *harness) {
	ctx := context.Background()

	cases := map[string]struct {
		carried captoken.Caveat
		breaks  func(req *captoken.Request)
	}{
		"an unknown content length": {
			carried: captoken.MaxContentLength(1024),
			breaks:  func(req *captoken.Request) { req.ContentLength = -1 },
		},
		"an unset client address": {
			carried: captoken.ClientCIDR(suiteClientPrefix),
			breaks:  func(req *captoken.Request) { req.ClientIP = netip.Addr{} },
		},
		"a resource path that never passed a schema": {
			carried: captoken.MaxContentLength(1024),
			breaks:  func(req *captoken.Request) { req.Resource = captoken.ResourcePath{} },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			presented := h.chainCarrying(t, w, tc.carried)
			if _, err := h.gateway.Verify(ctx, presented, h.request(w)); err != nil {
				t.Fatalf("Verify(a complete request) error = %v, want nil", err)
			}

			req := h.request(w)
			tc.breaks(&req)
			if _, err := h.gateway.Verify(ctx, presented, req); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
				t.Errorf("Verify(%s) error = %v, want wrapping ErrCaveatNotSatisfied", name, err)
			}
		})
	}
}

// testAnUnvalidatedResourceCannotBeMinted is the issuer's half of the same
// rule: a path that never passed a schema may not reach the wire, so the
// decoder can treat every path it reads as schema-checked by construction.
func testAnUnvalidatedResourceCannotBeMinted(t *testing.T, w Wiring, h *harness) {
	for name, mutate := range map[string]func(spec *captoken.MintSpec){
		"a resource path that never passed a schema": func(spec *captoken.MintSpec) {
			spec.Resources = []captoken.ResourcePath{{}}
		},
		"no resource at all": func(spec *captoken.MintSpec) { spec.Resources = nil },
		"no permission at all": func(spec *captoken.MintSpec) {
			spec.Permissions = captoken.NewPermissionSet()
		},
		// A capability with no expiry is a liability, and requiring one is
		// also what keeps the subsumption rule from ever having to reason
		// about a missing bound.
		"no expiry":         func(spec *captoken.MintSpec) { spec.ExpiresAt = time.Time{} },
		"no audience":       func(spec *captoken.MintSpec) { spec.Audience = nil },
		"an unknown type":   func(spec *captoken.MintSpec) { spec.Type = "transferable" },
		"an empty validity": func(spec *captoken.MintSpec) { spec.NotBefore = spec.ExpiresAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			spec := h.leafSpec(w)
			mutate(&spec)
			if _, err := h.minter.Mint(spec); !errors.Is(err, captoken.ErrInvalidToken) {
				t.Errorf("Mint(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}

	// An empty permission set and an empty resource list are never
	// "unrestricted" at check time either: a link that grants nothing
	// contributes nothing to the chain's intersection. That cannot be
	// minted, which is why it is asserted through CheckAll.
	for name, mutate := range map[string]func(g *captoken.Grant){
		"an empty permission set": func(g *captoken.Grant) { g.Permissions = captoken.NewPermissionSet() },
		"an empty resource list":  func(g *captoken.Grant) { g.Resources = nil },
	} {
		t.Run(name+" grants nothing", func(t *testing.T) {
			grant := h.grant(w)
			mutate(&grant)
			if err := captoken.CheckAll([]captoken.Grant{grant}, h.request(w)); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
				t.Errorf("CheckAll(a grant with %s) error = %v, want wrapping ErrCaveatNotSatisfied", name, err)
			}
		})
	}
}

// testChainDepthIsTheVerifiersToPopulate is the gate against a forgotten
// field in the other direction. DelegationDepth is checked against
// Request.ChainDepth, which a caller does NOT populate: the verifier fills
// it in from the chain it has just walked. So a caller cannot talk a
// verifier out of a depth bound by claiming a shallower chain, and a
// Request assembled by any other path — a consumer evaluating a chain in
// memory through CheckAll — fails closed on a depth below 1 rather than
// satisfying every bound.
func testChainDepthIsTheVerifiersToPopulate(t *testing.T, w Wiring, h *harness) {
	ctx := context.Background()
	presented := h.chainCarrying(t, w, captoken.DelegationDepth(2))

	// A caller claiming depth 1 for a two-link chain does not get the
	// bound of a one-link chain, nor escape the one it is subject to.
	lying := h.request(w)
	lying.ChainDepth = 1
	if _, err := h.gateway.Verify(ctx, presented, lying); err != nil {
		t.Errorf("Verify(a two-link chain whose caller claimed ChainDepth 1) error = %v, want nil: "+
			"the verifier must populate the depth from the chain it walked and ignore the caller's", err)
	}

	tighter := h.chainCarrying(t, w, captoken.DelegationDepth(1))
	generous := h.request(w)
	generous.ChainDepth = 1
	if _, err := h.gateway.Verify(ctx, tighter, generous); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
		t.Errorf("Verify(a two-link chain bounded at one link, whose caller claimed ChainDepth 1) "+
			"error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}

	// And through CheckAll, where nobody populated it at all.
	grant := h.grant(w)
	grant.Caveats = append(grant.Caveats, captoken.DelegationDepth(4))
	unpopulated := h.request(w)
	unpopulated.ChainDepth = 0
	if err := captoken.CheckAll([]captoken.Grant{grant}, unpopulated); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll(a grant bounding depth, against a request nobody populated the depth of) "+
			"error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

// ---- fixtures ------------------------------------------------------------

// grant is the in-memory equivalent of the suite's leaf link: a grant the
// base request satisfies, so a gate that refuses a mutation of it is
// refusing for the mutation.
//
// It is assembled rather than read out of a verified chain, deliberately:
// the point of CheckAll being exported is that a consumer can evaluate a
// chain it holds in memory, and such a chain gets the same fail-closed
// guarantees as a presented one.
func (h *harness) grant(w Wiring) captoken.Grant {
	return captoken.Grant{
		Subject:     "holder-1",
		Permissions: w.Narrow,
		Resources:   []captoken.ResourcePath{w.Inner},
		ExpiresAt:   suiteClock.Add(time.Hour),
		Caveats:     []captoken.Caveat{captoken.MaxContentLength(1 << 10)},
	}
}
