package captokentest

// This file holds the caveat vocabulary's half of the contract: that every
// one of the sixteen kinds is actually CHECKED when a token carries it, that
// every one of them ORDERS its own values the narrowing direction, and that
// none of them can be compared against a different kind.
//
// Why it exists at all: before it, the exported suite minted
// max_content_length and let the envelope carry exp, prm and res, which is
// five kinds. Eleven of the sixteen were exercised nowhere a consumer's CI
// could reach — their semantics were pinned only by
// internal/caveat/caveat_test.go, which no module outside captoken can
// import. A consumer could therefore not detect an implementation that
// accepted a caveat kind and then never evaluated it, which is a token that
// says it is narrowed and is not.
//
// # How a kind is exercised, and why it is the whole kind
//
// Each row below mints a two-link chain whose root carries the caveat and
// whose leaf restates it, and then asserts three things:
//
//  1. a request that satisfies the caveat verifies. Without this the other
//     two would pass against an implementation that refused everything.
//  2. a request that does not satisfy it is refused with
//     ErrCaveatNotSatisfied — the bare sentinel, never a cause that names
//     the kind. See testRefusalNamesNothing for why a more specific
//     assertion would be the wrong assertion.
//  3. a derivation that DROPS the kind is refused before it is signed.
//     Restating a parent's caveat is required rather than optional, which is
//     the rule that makes dropping one a widening by removal; asserting it
//     per kind is what stops an implementation restating twelve kinds and
//     forgetting the thirteenth.
//
// The chain is two links rather than one because a root-only chain has no
// parent to restate anything to, so (3) would have nowhere to happen.
//
// # The partition this file's two tables follow
//
// docs/wire-format.md carries four of the sixteen dimensions — expires_at,
// not_before, permission_set and resource_scope — as the standard claims
// exp, nbf, prm and res rather than as entries in the caveat array, so a
// third-party verifier using a stock JWT library checks them because its
// library does. They are therefore minted through MintSpec's own fields and
// not through MintSpec.Caveats, and they get a table of their own. Twelve
// kinds in the caveat table plus four standard claims is sixteen, and
// TestEveryRegisteredKindHasARow fails if the sum stops matching
// captoken.RegisteredKinds().
//
// # What the three stateful kinds can and cannot be held to here
//
// max_uses, expires_after_first_use and max_bytes_transferred read counters
// only the issuer holds, so they live only on a redemption token and need
// Wiring.Counters. Against an in-memory adapter the suite asserts
// everything that is a property of the CAVEAT: that the bound is enforced,
// that verification reads the counter and never advances it, that the
// first-use window starts at first use and not at issuance, and that bytes
// accumulate across requests. It also asserts the one property of the
// ADAPTER that does not need a transaction: that concurrent advances are
// not lost.
//
// What it cannot assert, and hands to the consumer, is atomicity of the
// whole redemption. The ordering the caveats require — read the counter,
// check, perform the operation, persist the advance, all in one
// transaction — is expressed nowhere in the Counters port, because a port
// that could express it would have to own the transaction, and the whole
// point is that the consumer's transaction owns the operation too. Two
// concurrent redemptions of a MaxUses(1) token can therefore both pass
// verification against any adapter, including a correct one, and only the
// consumer's own store can make them not both commit. A consumer must
// assert that against its real database. captokentest cannot, and a subtest
// here that appeared to would be worse than none.

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/laenenai/captoken"
)

// ---- the caveat table ----------------------------------------------------

// caveatCase is one row of testEveryCaveatKindIsChecked: a caveat value the
// base request satisfies, and one of the two ways to make it refuse.
type caveatCase struct {
	// kind is the registered kind the row covers, named so the table can be
	// checked against captoken.RegisteredKinds() rather than counted.
	kind string
	// satisfied is minted into both links of the chain.
	satisfied captoken.Caveat
	// refusingRequest changes one fact of the request so that satisfied no
	// longer holds. Nil for a kind whose refusal cannot be expressed as a
	// request fact.
	refusingRequest func(req *captoken.Request)
	// refusingValue is a value of the same kind that the base request does
	// NOT satisfy, minted into a second chain. Nil unless the kind's
	// refusal is about the chain rather than the request — delegation_depth
	// is the only such kind, because a chain's depth is not a request fact
	// a caller supplies.
	refusingValue captoken.Caveat
}

// caveatTable is the twelve kinds carried as entries in a token's caveat
// array. The other four are standard claims; see standardClaimTable.
func caveatTable(w Wiring) []caveatCase {
	f := w.Facts.withDefaults()

	return []caveatCase{
		{
			kind:      "allowed_content_types",
			satisfied: captoken.AllowedContentTypes{f.ContentType},
			// The parameter-smuggling case, which is the one this caveat is
			// shaped for: a sniffer never produces MIME parameters, so a
			// declared header a careless caller passed through instead of
			// sniffing fails the verbatim comparison with no special-case
			// logic.
			refusingRequest: func(req *captoken.Request) {
				req.ContentType = f.ContentType + "; charset=../../x"
			},
		},
		{
			kind:            "client_cidr",
			satisfied:       captoken.ClientCIDR(suiteClientPrefix),
			refusingRequest: func(req *captoken.Request) { req.ClientIP = suiteForeignIP },
		},
		{
			kind: "delegation_depth",
			// The chain below is two links, so a bound of 2 is satisfied and
			// a bound of 1 — "the root token itself, never derived" — is not.
			satisfied:     captoken.DelegationDepth(2),
			refusingValue: captoken.DelegationDepth(1),
		},
		{
			kind:            "max_content_length",
			satisfied:       captoken.MaxContentLength(1024),
			refusingRequest: func(req *captoken.Request) { req.ContentLength = 4096 },
		},
		{
			kind:            "processor_audience",
			satisfied:       captoken.ProcessorAudience(f.ProcessorIdentity),
			refusingRequest: func(req *captoken.Request) { req.ProcessorIdentity = "captokentest.other-processor" },
		},
		{
			kind:            "require_authenticated_recipient",
			satisfied:       captoken.RequireAuthenticatedRecipient{},
			refusingRequest: func(req *captoken.Request) { req.AuthenticatedRecipient = false },
		},
		{
			kind:            "require_declared_digest",
			satisfied:       captoken.RequireDeclaredDigest{},
			refusingRequest: func(req *captoken.Request) { req.DeclaredDigest = "" },
		},
		{
			kind:      "required_readiness",
			satisfied: captoken.RequiredReadiness{f.Readiness},
			// An empty readiness label is "nobody populated this" and
			// satisfies no state, which is the fail-closed direction.
			refusingRequest: func(req *captoken.Request) { req.Readiness = "" },
		},
		{
			kind:      "watermark",
			satisfied: captoken.Watermark(f.Rendition),
			// The empty rendition is the ORIGINAL, and refusing it is
			// exactly what this caveat is for: a token restricted to a
			// watermarked variant must not serve the unwatermarked bytes.
			refusingRequest: func(req *captoken.Request) { req.Rendition = "" },
		},

		// The three stateful kinds. They may appear only on a redemption
		// token, so they are exercised by testStatefulCaveatsEnforceTheir
		// Bounds rather than by the loop below; the rows are here so the
		// table is the whole vocabulary and the completeness check is a
		// check rather than a count.
		{kind: "max_uses", satisfied: captoken.MaxUses(2)},
		{kind: "expires_after_first_use", satisfied: captoken.ExpiresAfterFirstUse(10 * time.Minute)},
		{kind: "max_bytes_transferred", satisfied: captoken.MaxBytesTransferred(2048)},
	}
}

// standardClaimTable is the four dimensions docs/wire-format.md carries as
// standard JWT claims rather than as caveat-array entries. Each is minted
// through a MintSpec field, which is the only way to put one on the wire.
type standardClaimCase struct {
	kind string
	// mint sets the dimension on both links of the chain.
	mint func(spec *captoken.MintSpec)
	// refusingRequest changes one fact so the dimension refuses.
	refusingRequest func(req *captoken.Request)
}

func standardClaimTable(t *testing.T, w Wiring) []standardClaimCase {
	t.Helper()

	// A permission the chain never grants. Wiring.Narrow is a strict subset
	// of Wiring.Wide, so there is at least one, and taking it from the
	// consumer's own vocabulary is the point — a label the suite invented
	// would be refused by any implementation, including a broken one.
	var ungranted captoken.Permission
	for _, p := range w.Wide.Sorted() {
		if !w.Narrow.Contains(p) {
			ungranted = p
			break
		}
	}
	if ungranted == "" {
		t.Fatal("Wiring.Wide has no permission outside Wiring.Narrow, so prm cannot be exercised")
	}

	return []standardClaimCase{
		{
			kind: "expires_at",
			mint: func(spec *captoken.MintSpec) { spec.ExpiresAt = suiteClock.Add(time.Hour) },
			// Past the expiry AND past the clock-skew tolerance, which is
			// applied symmetrically and is a minute wide.
			refusingRequest: func(req *captoken.Request) { req.Now = suiteClock.Add(time.Hour + 2*time.Minute) },
		},
		{
			kind: "not_before",
			mint: func(spec *captoken.MintSpec) { spec.NotBefore = suiteClock.Add(30 * time.Minute) },
			// The base request is at suiteClock, which is half an hour
			// before the window opens, so this row's refusal needs no
			// change at all — but saying so explicitly keeps every row the
			// same shape.
			refusingRequest: func(req *captoken.Request) { req.Now = suiteClock },
		},
		{
			kind:            "permission_set",
			mint:            func(spec *captoken.MintSpec) { spec.Permissions = w.Narrow },
			refusingRequest: func(req *captoken.Request) { req.Permission = ungranted },
		},
		{
			kind:            "resource_scope",
			mint:            func(spec *captoken.MintSpec) { spec.Resources = []captoken.ResourcePath{w.Inner} },
			refusingRequest: func(req *captoken.Request) { req.Resource = w.Sibling },
		},
	}
}

// ---- the cases -----------------------------------------------------------

// testEveryCaveatKindIsChecked is the vocabulary's coverage property: a
// token that carries a caveat must be refused when the request does not
// satisfy it, and accepted when it does.
func testEveryCaveatKindIsChecked(t *testing.T, w Wiring, h *harness) {
	for _, tc := range caveatTable(w) {
		if captoken.IsStatefulKind(tc.kind) {
			continue // see testStatefulCaveatsEnforceTheirBounds
		}
		t.Run(tc.kind, func(t *testing.T) {
			presented := h.chainCarrying(t, w, tc.satisfied)

			if _, err := h.gateway.Verify(context.Background(), presented, h.request(w)); err != nil {
				t.Fatalf("Verify(a request this caveat permits) error = %v, want nil: "+
					"the refusals below would pass against a verifier that refused everything", err)
			}

			if tc.refusingRequest != nil {
				req := h.request(w)
				tc.refusingRequest(&req)
				if _, err := h.gateway.Verify(context.Background(), presented, req); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
					t.Errorf("Verify(a request this caveat does not permit) error = %v, "+
						"want wrapping ErrCaveatNotSatisfied", err)
				}
			}
			if tc.refusingValue != nil {
				refusing := h.chainCarrying(t, w, tc.refusingValue)
				if _, err := h.gateway.Verify(context.Background(), refusing, h.request(w)); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
					t.Errorf("Verify(a chain this caveat's value does not permit) error = %v, "+
						"want wrapping ErrCaveatNotSatisfied", err)
				}
			}

			// Restating the parent's caveat is required, not optional: a
			// child that simply omits it would be a token with no bound
			// derived from one that had a bound, which is a widening by
			// removal.
			root := h.rootCarrying(t, w, tc.satisfied)
			spec := h.leafSpec(w)
			spec.Caveats = nil
			if _, err := h.deriver.Derive(root.Token, root.HolderKey, spec); !errors.Is(err, captoken.ErrInvalidToken) {
				t.Errorf("Derive(a leaf that drops this caveat) error = %v, want wrapping ErrInvalidToken", err)
			}
		})
	}
}

// testEveryStandardClaimIsChecked is the same property for the four
// dimensions carried as exp, nbf, prm and res. They are not caveat-array
// entries, and nothing else enforces them: signature verification checks
// signatures, and the per-caveat loop never looks at a grant's own fields.
func testEveryStandardClaimIsChecked(t *testing.T, w Wiring, h *harness) {
	for _, tc := range standardClaimTable(t, w) {
		t.Run(tc.kind, func(t *testing.T) {
			rootSpec := h.rootSpec(w)
			rootSpec.Caveats = nil
			tc.mint(&rootSpec)
			root, err := h.minter.Mint(rootSpec)
			if err != nil {
				t.Fatalf("Mint() error = %v", err)
			}
			leafSpec := h.leafSpec(w)
			leafSpec.Caveats = nil
			tc.mint(&leafSpec)
			leaf, err := h.deriver.Derive(root.Token, root.HolderKey, leafSpec)
			if err != nil {
				t.Fatalf("Derive() error = %v", err)
			}

			// not_before is the one row whose satisfying instant is not the
			// suite's own: the window opens later than suiteClock, so the
			// control has to ask at an instant inside it.
			satisfying := h.request(w)
			if tc.kind == "not_before" {
				satisfying.Now = suiteClock.Add(40 * time.Minute)
			}
			if _, err := h.gateway.Verify(context.Background(), leaf.Token, satisfying); err != nil {
				t.Fatalf("Verify(a request this claim permits) error = %v, want nil", err)
			}

			req := h.request(w)
			tc.refusingRequest(&req)
			if _, err := h.gateway.Verify(context.Background(), leaf.Token, req); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
				t.Errorf("Verify(a request this claim does not permit) error = %v, "+
					"want wrapping ErrCaveatNotSatisfied", err)
			}
		})
	}
}

// testEveryRegisteredKindHasARow is what stops the two tables above
// drifting from the vocabulary. captoken.RegisteredKinds reports what the
// build understands, so a kind added without a row fails here instead of
// being exercised by nothing.
func testEveryRegisteredKindHasARow(t *testing.T, w Wiring, _ *harness) {
	covered := map[string]bool{}
	for _, tc := range caveatTable(w) {
		covered[tc.kind] = true
	}
	for _, tc := range standardClaimTable(t, w) {
		covered[tc.kind] = true
	}

	registered := captoken.RegisteredKinds()
	for _, kind := range registered {
		if !covered[kind] {
			t.Errorf("caveat kind %q is registered but no row in captokentest exercises it", kind)
		}
		delete(covered, kind)
	}
	for kind := range covered {
		t.Errorf("captokentest has a row for %q, which this build does not register", kind)
	}
	if len(registered) != len(narrowsTable(t, w)) {
		t.Errorf("%d kinds are registered but the narrowing table has %d rows",
			len(registered), len(narrowsTable(t, w)))
	}
}

// testAStandardClaimCannotBeACaveatEntry is the placement half of the
// partition, and a published MUST a consumer could not previously assert.
//
// docs/wire-format.md carries expires_at, not_before, permission_set and
// resource_scope ONLY as exp, nbf, prm and res, and requires a verifier to
// refuse one that appears in the caveat array. A token saying expires_at in
// both places says one thing to a reader of the claims and another to a
// reader of the caveat array, and nothing makes the two agree — so a
// lenient verifier and a conforming one would disagree about what the token
// permits, which is the interoperability failure the whole partition exists
// to prevent.
//
// A consumer provokes it at the only place it is reachable: minting. Once
// mint refuses, no token a consumer can produce carries one, so the
// verifier's own guard against an ARRIVING cav entry is reachable only from
// inside the module and internal/chain's adversarial suite owns it.
func testAStandardClaimCannotBeACaveatEntry(t *testing.T, w Wiring, h *harness) {
	standard := captoken.StandardClaimKinds()

	// The suite's own partition must be the module's. A kind that moved
	// from one table to the other would otherwise be exercised twice or
	// not at all.
	covered := map[string]bool{}
	for _, tc := range standardClaimTable(t, w) {
		covered[tc.kind] = true
	}
	for _, kind := range standard {
		if !covered[kind] {
			t.Errorf("%q is carried as a standard claim but captokentest exercises it as a caveat entry", kind)
		}
	}
	if len(standard) != len(covered) {
		t.Errorf("the module carries %d kinds as standard claims and captokentest's table has %d rows",
			len(standard), len(covered))
	}

	for _, c := range []captoken.Caveat{
		captoken.ExpiresAt(suiteClock.Add(30 * time.Minute)),
		captoken.NotBefore(suiteClock),
		captoken.PermissionSetCaveat(w.Narrow),
		captoken.ResourceScope{Scopes: []captoken.ResourcePath{w.Inner}},
	} {
		t.Run(c.Kind(), func(t *testing.T) {
			if !captoken.HasStandardClaim(c.Kind()) {
				t.Fatalf("%q is not reported as having a standard claim, so this case is testing nothing",
					c.Kind())
			}
			spec := h.leafSpec(w)
			spec.Caveats = append(spec.Caveats, c)
			if _, err := h.minter.Mint(spec); !errors.Is(err, captoken.ErrInvalidToken) {
				t.Errorf("Mint(%s as a caveat entry) error = %v, want wrapping ErrInvalidToken: "+
					"every conforming third-party verifier refuses such a token, so issuing one "+
					"issues a credential that works nowhere but here", c.Kind(), err)
			}
		})
	}
}

// testStatefulCaveatsEnforceTheirBounds is the three stateful kinds, each
// exhausted through the consumer's own Counters. See this file's header
// comment for what this can and cannot establish — in particular, that
// atomicity under concurrent redemption is the consumer's to assert against
// its real store and is not asserted here.
func testStatefulCaveatsEnforceTheirBounds(t *testing.T, w Wiring, h *harness) {
	if w.Counters == nil {
		t.Skip("Wiring.Counters is nil: a consumer that uses the stateful caveats must supply one")
	}
	ctx := context.Background()

	cases := map[string]struct {
		caveat captoken.Caveat
		// exhaust is the advance that uses the bound up, and partial an
		// advance that does not.
		partial captoken.Advance
		exhaust captoken.Advance
		// at is when the request after the exhausting advance is made,
		// which only the first-use window needs to move.
		at time.Time
	}{
		"max_uses": {
			caveat:  captoken.MaxUses(2),
			partial: captoken.Advance{Uses: 1},
			exhaust: captoken.Advance{Uses: 1},
		},
		"max_bytes_transferred": {
			// The request serves 512 bytes, so 1,024 already served leaves
			// room and 1,537 does not: the caveat bounds the bytes already
			// served PLUS this request's length.
			caveat:  captoken.MaxBytesTransferred(2048),
			partial: captoken.Advance{Bytes: 1024},
			exhaust: captoken.Advance{Bytes: 513},
		},
		"expires_after_first_use": {
			// The window starts at the chain's FIRST redemption, not at
			// issuance, which is the whole point of the kind: the advance
			// below pins first use at suiteClock, and the request after it
			// is made eleven minutes later — past the ten-minute window and
			// past the minute of clock-skew tolerance.
			caveat:  captoken.ExpiresAfterFirstUse(10 * time.Minute),
			partial: captoken.Advance{Uses: 1, FirstUsedAt: suiteClock},
			exhaust: captoken.Advance{},
			at:      suiteClock.Add(11*time.Minute + 1*time.Second),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			redemption := h.redemptionCarrying(t, w, tc.caveat)

			verified, err := h.reserver.Verify(ctx, redemption, h.request(w))
			if err != nil {
				t.Fatalf("Verify(a redemption token nothing has been spent against) error = %v, want nil", err)
			}

			// Verification reads the counters and never advances them, so a
			// bound is spent by the caller recording the advance and by
			// nothing else.
			before, err := w.Counters.Read(ctx, verified.ChainID)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if _, err := h.reserver.Verify(ctx, redemption, h.request(w)); err != nil {
				t.Fatalf("Verify() a second time error = %v, want nil", err)
			}
			if after, rerr := w.Counters.Read(ctx, verified.ChainID); rerr != nil || after != before {
				t.Fatalf("verification moved the counters from %+v to %+v (err = %v); it must only read them",
					before, after, rerr)
			}

			if err := w.Counters.Advance(ctx, verified.ChainID, tc.partial); err != nil {
				t.Fatalf("Advance(%+v) error = %v", tc.partial, err)
			}
			if _, err := h.reserver.Verify(ctx, redemption, h.request(w)); err != nil {
				t.Fatalf("Verify() after an advance that leaves room error = %v, want nil", err)
			}

			if err := w.Counters.Advance(ctx, verified.ChainID, tc.exhaust); err != nil {
				t.Fatalf("Advance(%+v) error = %v", tc.exhaust, err)
			}
			req := h.request(w)
			if !tc.at.IsZero() {
				req.Now = tc.at
			}
			if _, err := h.reserver.Verify(ctx, redemption, req); !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
				t.Errorf("Verify() once the bound is spent error = %v, want wrapping ErrCaveatNotSatisfied", err)
			}
		})
	}
}

// testCountersDoNotLoseConcurrentAdvances is the one property of the
// stateful subset the suite can hold a real adapter to without owning a
// transaction: Advance is additive, so N concurrent advances of one leave
// the counter at N, and FirstUsedAt is pinned by whichever advance recorded
// it first and never moved afterwards.
//
// It is NOT atomicity of a redemption, which no adapter can provide through
// this port — see this file's header comment. What it does catch is the
// read-modify-write an adapter writes when it implements Advance as a SELECT
// followed by an UPDATE outside a transaction, which silently loses uses
// under load and is exactly the bug that makes a MaxUses bound advisory.
//
// Sixteen goroutines, not more: the property is lost updates, which a
// handful of concurrent writers already exposes under -race, and a larger
// number only makes the subtest slower in every consumer's CI.
func testCountersDoNotLoseConcurrentAdvances(t *testing.T, w Wiring, _ *harness) {
	if w.Counters == nil {
		t.Skip("Wiring.Counters is nil")
	}
	ctx := context.Background()

	id, err := captoken.NewTokenID()
	if err != nil {
		t.Fatalf("NewTokenID() error = %v", err)
	}
	chain := captoken.ChainID(id)

	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each writer claims a different first-use instant, so the
			// pinning rule is exercised as well as the accumulation: only
			// the earliest-recorded one may survive, and no later advance
			// may move it.
			errs[i] = w.Counters.Advance(ctx, chain, captoken.Advance{
				Uses:        1,
				Bytes:       1,
				FirstUsedAt: suiteClock.Add(time.Duration(i) * time.Second),
			})
		}()
	}
	wg.Wait()
	for i, aerr := range errs {
		if aerr != nil {
			t.Fatalf("Advance() from writer %d error = %v", i, aerr)
		}
	}

	got, err := w.Counters.Read(ctx, chain)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got.Uses != writers || got.BytesTransferred != writers {
		t.Errorf("after %d concurrent advances of one use and one byte, Uses = %d and BytesTransferred = %d, "+
			"want %d and %d: an advance implemented as a read followed by a write outside a transaction "+
			"loses updates exactly this way, which makes every stateful bound advisory",
			writers, got.Uses, got.BytesTransferred, writers, writers)
	}
	if got.FirstUsedAt.IsZero() {
		t.Error("FirstUsedAt is zero after advances that all supplied one")
	}
	if err := w.Counters.Advance(ctx, chain, captoken.Advance{FirstUsedAt: suiteClock.Add(time.Hour)}); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	moved, err := w.Counters.Read(ctx, chain)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !moved.FirstUsedAt.Equal(got.FirstUsedAt) {
		t.Errorf("FirstUsedAt moved from %v to %v; a later advance must never move it, or a first-use "+
			"window could be reopened by using the token again", got.FirstUsedAt, moved.FirstUsedAt)
	}
}

// ---- the narrowing order -------------------------------------------------

// narrowsCase is one row of testEveryKindOrdersItsOwnValues: parent is some
// value of the kind, narrower must narrow it, and wider must not.
type narrowsCase struct {
	kind     string
	parent   captoken.Caveat
	narrower captoken.Caveat
	// wider is nil for the two presence flags, whose only same-kind
	// comparison is equality: there is no value "wider than present".
	wider captoken.Caveat
}

// narrowsTable is every kind, with a value ordering in both directions. It
// is the table internal/caveat's own tests have had since the vocabulary was
// extracted, written here against the consumer's schema and permission sets
// so that the comparison a consumer's tokens will actually be subject to is
// the one that gets checked.
func narrowsTable(t *testing.T, w Wiring) []narrowsCase {
	t.Helper()

	// A permission set strictly wider than the consumer's Wide. This is the
	// one place the suite invents a label: Narrows is pure set arithmetic
	// over opaque strings — it never parses or mints them — and no set the
	// consumer declared is wider than the widest one it declared.
	widest := captoken.NewPermissionSet(append(w.Wide.Sorted(), "captokentest.extra-permission")...)

	scope := func(p captoken.ResourcePath) captoken.ResourceScope {
		return captoken.ResourceScope{Scopes: []captoken.ResourcePath{p}}
	}

	return []narrowsCase{
		{
			kind:     "expires_at",
			parent:   captoken.ExpiresAt(suiteClock),
			narrower: captoken.ExpiresAt(suiteClock.Add(-time.Hour)),
			wider:    captoken.ExpiresAt(suiteClock.Add(time.Hour)),
		},
		{
			kind:     "not_before",
			parent:   captoken.NotBefore(suiteClock),
			narrower: captoken.NotBefore(suiteClock.Add(time.Hour)),
			wider:    captoken.NotBefore(suiteClock.Add(-time.Hour)),
		},
		{
			kind:     "expires_after_first_use",
			parent:   captoken.ExpiresAfterFirstUse(2 * time.Hour),
			narrower: captoken.ExpiresAfterFirstUse(time.Hour),
			wider:    captoken.ExpiresAfterFirstUse(3 * time.Hour),
		},
		{
			kind:     "max_uses",
			parent:   captoken.MaxUses(5),
			narrower: captoken.MaxUses(3),
			wider:    captoken.MaxUses(10),
		},
		{
			kind:     "resource_scope",
			parent:   scope(w.Outer),
			narrower: scope(w.Inner),
			// Sideways, not outwards: a sibling the parent does not contain
			// is not narrower, and a containment that cannot be proven does
			// not narrow. That is the case a flattened scope string gets
			// wrong.
			wider: scope(w.Sibling),
		},
		{
			kind:     "permission_set",
			parent:   captoken.PermissionSetCaveat(w.Wide),
			narrower: captoken.PermissionSetCaveat(w.Narrow),
			wider:    captoken.PermissionSetCaveat(widest),
		},
		{
			kind:     "max_content_length",
			parent:   captoken.MaxContentLength(1000),
			narrower: captoken.MaxContentLength(500),
			wider:    captoken.MaxContentLength(2000),
		},
		{
			kind:     "allowed_content_types",
			parent:   captoken.AllowedContentTypes{"application/pdf", "image/png"},
			narrower: captoken.AllowedContentTypes{"application/pdf"},
			wider:    captoken.AllowedContentTypes{"application/pdf", "application/zip", "image/png"},
		},
		{
			kind:     "max_bytes_transferred",
			parent:   captoken.MaxBytesTransferred(1000),
			narrower: captoken.MaxBytesTransferred(500),
			wider:    captoken.MaxBytesTransferred(2000),
		},
		{
			kind:     "require_authenticated_recipient",
			parent:   captoken.RequireAuthenticatedRecipient{},
			narrower: captoken.RequireAuthenticatedRecipient{},
			wider:    nil,
		},
		{
			kind:     "required_readiness",
			parent:   captoken.RequiredReadiness{"quarantined", "ready"},
			narrower: captoken.RequiredReadiness{"ready"},
			wider:    captoken.RequiredReadiness{"pending", "quarantined", "ready"},
		},
		{
			kind:     "require_declared_digest",
			parent:   captoken.RequireDeclaredDigest{},
			narrower: captoken.RequireDeclaredDigest{},
			wider:    nil,
		},
		{
			kind:     "client_cidr",
			parent:   mustPrefixCaveat(t, "10.0.0.0/8"),
			narrower: mustPrefixCaveat(t, "10.1.0.0/16"),
			wider:    mustPrefixCaveat(t, "0.0.0.0/0"),
		},
		{
			kind:     "delegation_depth",
			parent:   captoken.DelegationDepth(5),
			narrower: captoken.DelegationDepth(3),
			wider:    captoken.DelegationDepth(10),
		},
		{
			kind:   "processor_audience",
			parent: captoken.ProcessorAudience("captokentest.processor-a"),
			// Exact match only: an audience caveat cannot be redirected to
			// another processor, only kept.
			narrower: captoken.ProcessorAudience("captokentest.processor-a"),
			wider:    captoken.ProcessorAudience("captokentest.processor-b"),
		},
		{
			kind:     "watermark",
			parent:   captoken.Watermark("captokentest.rendition-a"),
			narrower: captoken.Watermark("captokentest.rendition-a"),
			wider:    captoken.Watermark("captokentest.rendition-b"),
		},
	}
}

// testEveryKindOrdersItsOwnValues is the subsumption discipline at the level
// of a single caveat: whatever a kind means, it must be able to say which of
// two of its values is the more restrictive, and it must say so in the right
// direction.
//
// It is reachable through the exported surface because every caveat type is
// exported and Narrows is on the Caveat interface. A consumer that could not
// assert it could not detect an implementation whose Narrows was inverted
// for one kind — which would be a build where a derivation widens its parent
// in that dimension and verification agrees.
func testEveryKindOrdersItsOwnValues(t *testing.T, w Wiring, _ *harness) {
	for _, tc := range narrowsTable(t, w) {
		t.Run(tc.kind, func(t *testing.T) {
			if !tc.narrower.Narrows(tc.parent) {
				t.Errorf("the narrower value does not narrow the parent")
			}
			if tc.wider != nil && tc.wider.Narrows(tc.parent) {
				t.Errorf("the wider value narrows the parent, so a derivation could widen this dimension")
			}
			if !tc.parent.Narrows(tc.parent) {
				t.Errorf("a value does not narrow itself, so a derivation that restated it unchanged " +
					"would be refused")
			}
		})
	}
}

// testNoKindNarrowsAnother is the other half, and the shape of bug a
// careless type assertion in a Narrows implementation introduces: comparing
// two DIFFERENT kinds must always refuse, because nothing can be proven
// about an ordering across kinds.
//
// Sixteen kinds is 256 ordered pairs, of which the 16 same-kind ones are the
// subtest above, leaving 240. That is exhaustive rather than sampled, and it
// is affordable because a Narrows call does no I/O and no cryptography: the
// whole table runs in well under a millisecond. It is the one combinatorial
// space in this file that needs no bound.
func testNoKindNarrowsAnother(t *testing.T, w Wiring, _ *harness) {
	table := narrowsTable(t, w)
	samples := make([]captoken.Caveat, len(table))
	for i, tc := range table {
		samples[i] = tc.parent
	}

	pairs := 0
	for i, child := range samples {
		for j, parent := range samples {
			if i == j {
				continue
			}
			pairs++
			if child.Narrows(parent) {
				t.Errorf("a %s caveat narrows a %s caveat; a comparison across kinds must always refuse",
					table[i].kind, table[j].kind)
			}
		}
	}
	if want := len(table) * (len(table) - 1); pairs != want {
		t.Errorf("checked %d cross-kind pairs, want %d", pairs, want)
	}
}

// ---- fixtures ------------------------------------------------------------

// rootCarrying mints a delegation root whose only caveat is the one given,
// so a row's failure is attributable to that kind and not to a ceiling the
// suite's standard fixture happened to carry.
func (h *harness) rootCarrying(t *testing.T, w Wiring, c captoken.Caveat) captoken.Minted {
	t.Helper()
	spec := h.rootSpec(w)
	spec.Caveats = []captoken.Caveat{c}
	root, err := h.minter.Mint(spec)
	if err != nil {
		t.Fatalf("Mint(a root carrying a %s caveat) error = %v", c.Kind(), err)
	}
	return root
}

// chainCarrying mints root(delegation) -> leaf(execution) with both links
// carrying c, which is what the restatement rule requires of any chain.
func (h *harness) chainCarrying(t *testing.T, w Wiring, c captoken.Caveat) string {
	t.Helper()
	root := h.rootCarrying(t, w, c)
	spec := h.leafSpec(w)
	spec.Caveats = []captoken.Caveat{c}
	leaf, err := h.deriver.Derive(root.Token, root.HolderKey, spec)
	if err != nil {
		t.Fatalf("Derive(a leaf restating a %s caveat) error = %v", c.Kind(), err)
	}
	return leaf.Token
}

// redemptionCarrying mints root(delegation) -> leaf(redemption) with the
// stateful caveat on the leaf and nothing on the root.
//
// The root carries no caveat of that kind deliberately: a stateful caveat
// may appear only on a terminal redemption link, so the restatement rule
// must not be asking an interior link to carry one.
func (h *harness) redemptionCarrying(t *testing.T, w Wiring, c captoken.Caveat) string {
	t.Helper()
	rootSpec := h.rootSpec(w)
	rootSpec.Caveats = nil
	root, err := h.minter.Mint(rootSpec)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	spec := h.leafSpec(w)
	spec.Type = captoken.TypeRedemption
	spec.Audience = []captoken.Audience{suiteReserver}
	spec.Caveats = []captoken.Caveat{c}
	leaf, err := h.deriver.Derive(root.Token, root.HolderKey, spec)
	if err != nil {
		t.Fatalf("Derive(a redemption token carrying a %s caveat) error = %v", c.Kind(), err)
	}
	return leaf.Token
}

// mustPrefixCaveat parses a CIDR into a ClientCIDR caveat. A masked prefix
// is the only canonical form, so the literals above are already masked.
func mustPrefixCaveat(t *testing.T, s string) captoken.ClientCIDR {
	t.Helper()
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q) error = %v", s, err)
	}
	return captoken.ClientCIDR(prefix)
}
