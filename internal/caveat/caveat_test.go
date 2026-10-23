package caveat_test

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/laenenai/captoken/internal/caveat"
	"github.com/laenenai/captoken/internal/domain"
)

// This file is cas/internal/token/caveat_test.go, carried across. Every
// test that encoded a bug someone had already found is here under its own
// name; the ones whose subject was cas's own resource model are re-landed
// against domain.ResourceSchema rather than dropped. See the package doc
// comment for what changed and why.

// casSchema is the hierarchy CAS declares. These tests use it because the
// ported cases are expressed against it.
func casSchema(t *testing.T) domain.ResourceSchema {
	t.Helper()
	s, err := domain.NewResourceSchema(
		domain.SegmentKind{Name: "tenant"},
		domain.SegmentKind{Name: "fileset", Repeats: true},
		domain.SegmentKind{Name: "document"},
		domain.SegmentKind{Name: "slot"},
		domain.SegmentKind{Name: "element"},
	)
	if err != nil {
		t.Fatalf("NewResourceSchema() error = %v", err)
	}
	return s
}

func path(t *testing.T, segs ...domain.Segment) domain.ResourcePath {
	t.Helper()
	p, err := casSchema(t).Path(segs...)
	if err != nil {
		t.Fatalf("Path(%v) error = %v", segs, err)
	}
	return p
}

func seg(kind, id string) domain.Segment { return domain.Segment{Kind: kind, ID: id} }

func doc1(t *testing.T) domain.ResourcePath {
	t.Helper()
	return path(t, seg("tenant", "tenant-1"), seg("document", "doc-1"))
}

func baseRequest(t *testing.T, now time.Time) caveat.Request {
	t.Helper()
	return caveat.Request{
		Now:           now,
		Permission:    "doc.read_content",
		Resource:      doc1(t),
		ClientIP:      netip.MustParseAddr("10.0.0.5"),
		ContentLength: 100,
		ContentType:   "application/pdf",
		ChainDepth:    1,
	}
}

func checkOK(t *testing.T, c caveat.Caveat, req caveat.Request) {
	t.Helper()
	if err := c.Check(req); err != nil {
		t.Errorf("%T.Check() error = %v, want nil", c, err)
	}
}

func checkFails(t *testing.T, c caveat.Caveat, req caveat.Request) {
	t.Helper()
	if err := c.Check(req); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("%T.Check() error = %v, want wrapping caveat.ErrCaveatNotSatisfied", c, err)
	}
}

// testGrant returns a grant whose own fields match baseRequest, for tests
// that need checkGrantFields (permission membership, resource containment)
// to pass so they can isolate whatever they are actually exercising.
func testGrant(t *testing.T, caveats ...caveat.Caveat) caveat.Grant {
	t.Helper()
	return caveat.Grant{
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{doc1(t)},
		Caveats:     caveats,
	}
}

func TestCheckAll_UnionOfCaveatsAcrossLinksAllMustPass(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	grants := []caveat.Grant{
		testGrant(t, caveat.PermissionSet(domain.NewPermissionSet("doc.read_content"))),
		testGrant(t, caveat.ExpiresAt(now.Add(time.Hour))),
	}

	req := baseRequest(t, now)
	if err := caveat.CheckAll(grants, req); err != nil {
		t.Fatalf("CheckAll() error = %v, want nil (both caveats satisfied)", err)
	}

	wrongPermission := req
	wrongPermission.Permission = "doc.delete"
	if err := caveat.CheckAll(grants, wrongPermission); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() with wrong permission error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}

	expired := req
	expired.Now = now.Add(2 * time.Hour)
	if err := caveat.CheckAll(grants, expired); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() with an expired link error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

// TestCheckAll_EnforcesGrantExpiry and the three tests after it are cas's
// C3 scenarios: four Grant fields that nothing else enforces. Verification
// checks signatures only, and the per-caveat loop never looks at them, so
// before CheckAll took responsibility a link whose ExpiresAt had passed —
// or which never granted the requested permission — verified and passed.
func TestCheckAll_EnforcesGrantExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now()

	g := testGrant(t)
	g.Permissions = domain.NewPermissionSet("doc.erase_content_everywhere")
	g.ExpiresAt = now.Add(-24 * time.Hour)

	req := baseRequest(t, now)
	req.Permission = "doc.erase_content_everywhere"
	if err := caveat.CheckAll([]caveat.Grant{g}, req); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() with a link expired 24h ago error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

func TestCheckAll_EnforcesGrantNotBefore(t *testing.T) {
	t.Parallel()
	now := time.Now()

	g := testGrant(t)
	g.NotBefore = now.Add(time.Hour)

	if err := caveat.CheckAll([]caveat.Grant{g}, baseRequest(t, now)); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() before a link's NotBefore error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
	if err := caveat.CheckAll([]caveat.Grant{g}, baseRequest(t, now.Add(2*time.Hour))); err != nil {
		t.Errorf("CheckAll() after a link's NotBefore error = %v, want nil", err)
	}
}

func TestCheckAll_EnforcesGrantPermissionMembership(t *testing.T) {
	t.Parallel()

	g := testGrant(t)
	g.Permissions = domain.NewPermissionSet("doc.read_metadata")

	req := baseRequest(t, time.Now())
	req.Permission = "doc.erase_content_everywhere" // never granted by this link
	if err := caveat.CheckAll([]caveat.Grant{g}, req); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() for a permission the link never granted error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

func TestCheckAll_EnforcesGrantResourceContainment(t *testing.T) {
	t.Parallel()

	g := testGrant(t)
	g.Resources = []domain.ResourcePath{path(t, seg("tenant", "tenant-1"), seg("document", "doc-OTHER"))}

	if err := caveat.CheckAll([]caveat.Grant{g}, baseRequest(t, time.Now())); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() for a resource outside the link's Resources error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

// TestCheckAll_EmptyPermissionsOrResourcesGrantNothing pins the half of
// cas's checkBlockFields contract that reads the other way round from the
// time bounds: a zero NotBefore or ExpiresAt means "no bound", but an EMPTY
// permission or resource set is never "unrestricted" — it is a link that
// grants nothing and contributes an empty set to the chain's intersection.
func TestCheckAll_EmptyPermissionsOrResourcesGrantNothing(t *testing.T) {
	t.Parallel()
	req := baseRequest(t, time.Now())

	noPerms := testGrant(t)
	noPerms.Permissions = nil
	if err := caveat.CheckAll([]caveat.Grant{noPerms}, req); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() with an empty permission set error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}

	noResources := testGrant(t)
	noResources.Resources = nil
	if err := caveat.CheckAll([]caveat.Grant{noResources}, req); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("CheckAll() with an empty resource list error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

func TestGrant_NarrowsPermissions(t *testing.T) {
	t.Parallel()

	parent := caveat.Grant{Permissions: domain.NewPermissionSet("doc.read_content", "doc.tag")}
	narrower := caveat.Grant{Permissions: domain.NewPermissionSet("doc.read_content")}
	wider := caveat.Grant{Permissions: domain.NewPermissionSet("doc.read_content", "doc.delete")}
	empty := caveat.Grant{}

	if !narrower.NarrowsPermissions(parent) {
		t.Error("a subset of parent's permissions must narrow")
	}
	if wider.NarrowsPermissions(parent) {
		t.Error("a permission the parent never granted must not narrow (that would widen)")
	}
	if !empty.NarrowsPermissions(parent) {
		t.Error("an empty permission set must narrow any parent (nothing to widen)")
	}
	if !parent.NarrowsPermissions(parent) {
		t.Error("a grant must narrow itself")
	}
}

func TestGrant_NarrowsResources(t *testing.T) {
	t.Parallel()

	doc1 := doc1(t)
	doc2 := path(t, seg("tenant", "tenant-1"), seg("document", "doc-2"))
	tenant := path(t, seg("tenant", "tenant-1"))

	parent := caveat.Grant{Resources: []domain.ResourcePath{doc1}}

	if !(caveat.Grant{Resources: []domain.ResourcePath{doc1}}).NarrowsResources(parent) {
		t.Error("the same resource scope must narrow (reflexive)")
	}
	if (caveat.Grant{Resources: []domain.ResourcePath{tenant}}).NarrowsResources(parent) {
		t.Error("a tenant-wide scope must not narrow a single-document parent (that would widen)")
	}
	if (caveat.Grant{Resources: []domain.ResourcePath{doc2}}).NarrowsResources(parent) {
		t.Error("a resource outside the parent's scope must not narrow")
	}
	if !(caveat.Grant{}).NarrowsResources(parent) {
		t.Error("an empty resource list must narrow any parent (nothing to widen)")
	}

	// An unvalidated child path cannot be proven to narrow: mint time must
	// refuse what it cannot verify, not assume it is safe.
	var unvalidated domain.ResourcePath
	if (caveat.Grant{Resources: []domain.ResourcePath{unvalidated}}).NarrowsResources(parent) {
		t.Error("an unvalidated resource path must not narrow (fail closed, not fail open)")
	}
}

func TestExpiresAt_RespectsSkewToleranceSymmetrically(t *testing.T) {
	t.Parallel()
	exp := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	c := caveat.ExpiresAt(exp)

	checkOK(t, c, baseRequest(t, exp.Add(30*time.Second)))    // 30s past expiry, within 60s skew
	checkFails(t, c, baseRequest(t, exp.Add(90*time.Second))) // 90s past expiry, beyond 60s skew
}

func TestNotBefore_RespectsSkewToleranceSymmetrically(t *testing.T) {
	t.Parallel()
	nbf := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	c := caveat.NotBefore(nbf)

	checkOK(t, c, baseRequest(t, nbf.Add(-30*time.Second)))    // 30s early, within skew
	checkFails(t, c, baseRequest(t, nbf.Add(-90*time.Second))) // 90s early, beyond skew
}

func TestResourceScope_DocumentCaveatRejectsSiblingDocument(t *testing.T) {
	t.Parallel()
	scope := caveat.ResourceScope{Scopes: []domain.ResourcePath{doc1(t)}}

	req := baseRequest(t, time.Now())
	checkOK(t, scope, req) // same document

	sibling := req
	sibling.Resource = path(t, seg("tenant", "tenant-1"), seg("document", "doc-2"))
	checkFails(t, scope, sibling)
}

// TestResourceScope_RejectsSiblingPrefixedFileset is the regression test for
// the bug the Biscuit spike demonstrated in the alternative design: scope
// "fs/a" matching sibling "fs/ab" because a flattened scope string makes
// containment a .starts_with. Segment-wise comparison cannot do this, and
// this test is what stops anyone flattening it later.
func TestResourceScope_RejectsSiblingPrefixedFileset(t *testing.T) {
	t.Parallel()
	scope := caveat.ResourceScope{Scopes: []domain.ResourcePath{
		path(t, seg("tenant", "tenant-1"), seg("fileset", "a")),
	}}

	req := baseRequest(t, time.Now())
	req.Resource = path(t, seg("tenant", "tenant-1"), seg("fileset", "ab"), seg("document", "doc-1"))
	checkFails(t, scope, req)

	inScope := req
	inScope.Resource = path(t, seg("tenant", "tenant-1"), seg("fileset", "a"), seg("document", "doc-1"))
	checkOK(t, scope, inScope)
}

func TestResourceScope_SlotSeriesElementIsNarrowerThanSeries(t *testing.T) {
	t.Parallel()

	seriesPath := path(t, seg("tenant", "tenant-1"), seg("document", "doc-1"), seg("slot", "pages"))
	elementPath := path(t,
		seg("tenant", "tenant-1"), seg("document", "doc-1"), seg("slot", "pages"), seg("element", "3"))

	series := caveat.ResourceScope{Scopes: []domain.ResourcePath{seriesPath}}
	element := caveat.ResourceScope{Scopes: []domain.ResourcePath{elementPath}}

	if !element.Narrows(series) {
		t.Error("a single slot element's ResourceScope must narrow its series' ResourceScope")
	}
	if series.Narrows(element) {
		t.Error("a series' ResourceScope must NOT narrow a single element's ResourceScope (that would widen)")
	}

	req := baseRequest(t, time.Now())
	req.Resource = elementPath
	checkOK(t, series, req)

	req.Resource = seriesPath
	checkFails(t, element, req)
}

// TestResourceScope_UnionWithinACaveatIntersectionAcrossThem pins the one
// deliberate merge in this extraction: cas had both a Block.Resources list
// (union, "contained by at least one") and a single-scope ResourceScope
// caveat, and they are the same dimension said twice. Here one caveat holds
// a set with union semantics, and two caveats of the kind intersect, which
// is exactly what CheckAll's all-must-pass loop already does.
func TestResourceScope_UnionWithinACaveatIntersectionAcrossThem(t *testing.T) {
	t.Parallel()

	a := path(t, seg("tenant", "tenant-1"), seg("fileset", "a"))
	b := path(t, seg("tenant", "tenant-1"), seg("fileset", "b"))
	inA := path(t, seg("tenant", "tenant-1"), seg("fileset", "a"), seg("document", "doc-1"))

	union := caveat.ResourceScope{Scopes: []domain.ResourcePath{a, b}}
	req := baseRequest(t, time.Now())
	req.Resource = inA
	checkOK(t, union, req)

	onlyB := caveat.ResourceScope{Scopes: []domain.ResourcePath{b}}
	if err := caveat.CheckAll([]caveat.Grant{{
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{a, b},
		Caveats:     []caveat.Caveat{union, onlyB},
	}}, req); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Error("two ResourceScope caveats must intersect: a resource in only one of them must be refused")
	}
}

// TestResourceScope_RefusesRatherThanIgnoresUnvalidatedRequestResource is
// cas's fail-closed ruling on an unresolved resource reference, re-landed.
// A caller passing an unvalidated Request.Resource must not get a silent
// "not in scope, so denied": that is indistinguishable from an ordinary
// deny on the outside, and also from the dangerous case where the resource
// actually WAS in scope and the missing data hid it. What this pins is that
// the containment error drives the refusal, not an accidental false.
func TestResourceScope_RefusesRatherThanIgnoresUnvalidatedRequestResource(t *testing.T) {
	t.Parallel()
	scope := caveat.ResourceScope{Scopes: []domain.ResourcePath{doc1(t)}}

	req := baseRequest(t, time.Now())
	var unvalidated domain.ResourcePath
	req.Resource = unvalidated

	if _, err := scope.Scopes[0].Contains(req.Resource); !errors.Is(err, domain.ErrUnresolvedResourcePath) {
		t.Fatalf("Contains() on the unvalidated request resource error = %v, want wrapping ErrUnresolvedResourcePath", err)
	}
	checkFails(t, scope, req)
}

func TestMaxContentLength_RejectsLargerUploadIncludingUnknownLength(t *testing.T) {
	t.Parallel()
	c := caveat.MaxContentLength(1000)

	req := baseRequest(t, time.Now())
	req.ContentLength = 1000
	checkOK(t, c, req)

	tooLarge := req
	tooLarge.ContentLength = 1001
	checkFails(t, c, tooLarge)

	unknown := req
	unknown.ContentLength = -1
	checkFails(t, c, unknown)
}

func TestAllowedContentTypes_RejectsParameterSmuggling(t *testing.T) {
	t.Parallel()
	c := caveat.AllowedContentTypes{"application/pdf"}

	req := baseRequest(t, time.Now())
	req.ContentType = "application/pdf; charset=../../x"
	checkFails(t, c, req)
}

func TestAllowedContentTypes_MatchesSniffedTypeNotTheDeclaredHeader(t *testing.T) {
	t.Parallel()
	c := caveat.AllowedContentTypes{"application/pdf"}

	// The uploader declared "application/pdf" via a header, but the caller
	// sniffed the actual bytes and found a ZIP; Request.ContentType must
	// carry the sniffed value ("application/zip"), which this caveat then
	// correctly rejects — the declared header is never consulted at all.
	req := baseRequest(t, time.Now())
	req.ContentType = "application/zip"
	checkFails(t, c, req)

	req.ContentType = "application/pdf"
	checkOK(t, c, req)
}

func TestMaxUses_ExhaustsAfterNRedemptionsAndIsAtomicUnderRace(t *testing.T) {
	t.Parallel()
	c := caveat.MaxUses(3)
	req := baseRequest(t, time.Now())

	for uses := range 3 {
		r := req
		r.UsesBefore = uses
		checkOK(t, c, r)
	}
	for uses := 3; uses < 6; uses++ {
		r := req
		r.UsesBefore = uses
		checkFails(t, c, r)
	}

	// Check itself holds no mutable shared state: calling it from many
	// goroutines with a fixed snapshot must never race and must always
	// agree. The atomic read-check-increment against concurrent
	// redemptions is the reservation port's job, against its own counter,
	// not this caveat's.
	atLimit := req
	atLimit.UsesBefore = 2
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Check(atLimit); err != nil {
				t.Errorf("concurrent Check() with UsesBefore=2 against MaxUses(3) error = %v, want nil", err)
			}
		}()
	}
	wg.Wait()
}

func TestExpiresAfterFirstUse_WindowStartsAtFirstRedemptionNotIssuance(t *testing.T) {
	t.Parallel()
	c := caveat.ExpiresAfterFirstUse(time.Hour)
	issuedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Never used: passes no matter how long after issuance, since the
	// window has not started.
	checkOK(t, c, baseRequest(t, issuedAt.Add(365*24*time.Hour)))

	// First used long after issuance: the window starts there, not at
	// issuance.
	firstUse := issuedAt.Add(30 * 24 * time.Hour)
	withinWindow := baseRequest(t, firstUse.Add(30*time.Minute))
	withinWindow.FirstUsedAt = firstUse
	checkOK(t, c, withinWindow)

	afterWindow := baseRequest(t, firstUse.Add(2*time.Hour))
	afterWindow.FirstUsedAt = firstUse
	checkFails(t, c, afterWindow)
}

func TestMaxBytesTransferred_AccumulatesAcrossUsesAndRefusesWhenExceeded(t *testing.T) {
	t.Parallel()
	c := caveat.MaxBytesTransferred(1000)

	req := baseRequest(t, time.Now())
	req.BytesTransferredBefore = 900
	req.ContentLength = 100
	checkOK(t, c, req) // exactly at the limit

	req.ContentLength = 101
	checkFails(t, c, req)

	unknown := req
	unknown.ContentLength = -1
	checkFails(t, c, unknown)
}

// TestMaxBytesTransferred_RejectsOverflowingContentLength reproduces cas's
// C5 probe exactly: ContentLength is attacker-declared on an upload
// (net/http parses an arbitrarily large Content-Length header without
// complaint), so Check(before=1, len=math.MaxInt64) used to add the two
// before comparing against the limit — 1 + math.MaxInt64 overflows int64
// and wraps negative, which is never greater than any positive limit, so
// the caveat passed a request for more bytes than any token could
// legitimately authorize.
func TestMaxBytesTransferred_RejectsOverflowingContentLength(t *testing.T) {
	t.Parallel()
	c := caveat.MaxBytesTransferred(1000)

	req := baseRequest(t, time.Now())
	req.BytesTransferredBefore = 1
	req.ContentLength = math.MaxInt64
	checkFails(t, c, req)

	// A negative BytesTransferredBefore is equally nonsensical (the
	// reservation's counter should never produce one, but Check must not
	// trust that) and must not be used to manufacture room via the same
	// subtraction.
	negativeCounter := baseRequest(t, time.Now())
	negativeCounter.BytesTransferredBefore = -1
	negativeCounter.ContentLength = 500
	checkFails(t, c, negativeCounter)
}

func TestMaxBytesTransferred_PartialTransferCountsBytesActuallyServed(t *testing.T) {
	t.Parallel()
	c := caveat.MaxBytesTransferred(1000)

	// First use declares a 600-byte upload but the connection drops after
	// 200 bytes actually served; the caller must record 200, not 600, as
	// the running total. Demonstrate that a second request computed
	// against the ACTUAL served total (200) still has room, while one
	// computed against the DECLARED total (600) would have wrongly refused
	// it.
	actualServed := baseRequest(t, time.Now())
	actualServed.BytesTransferredBefore = 200
	actualServed.ContentLength = 700
	checkOK(t, c, actualServed) // 200 + 700 = 900 <= 1000

	declared := actualServed
	declared.BytesTransferredBefore = 600
	checkFails(t, c, declared) // 600 + 700 = 1300 > 1000
}

func TestRequireAuthenticatedRecipient_RejectsAnonymousBearer(t *testing.T) {
	t.Parallel()
	c := caveat.RequireAuthenticatedRecipient{}

	req := baseRequest(t, time.Now())
	checkFails(t, c, req) // AuthenticatedRecipient defaults to false

	req.AuthenticatedRecipient = true
	checkOK(t, c, req)
}

func TestRequireDeclaredDigest_RejectsUploadWithNoDeclaredAddress(t *testing.T) {
	t.Parallel()
	c := caveat.RequireDeclaredDigest{}

	req := baseRequest(t, time.Now())
	checkFails(t, c, req)

	req.DeclaredDigest = "sha256:" + strings.Repeat("ab", 32)
	checkOK(t, c, req)
}

// TestStatefulCaveats_DoNotAdvanceWhenTheOperationFails is the test that
// encodes the ordering discipline, and it is kept verbatim in intent. Check
// is a pure read of the snapshot it is given; calling it repeatedly with
// the identical Request must always agree, proving it has no hidden
// internal counter of its own that a failed caller could have silently
// advanced. The caller owns the only mutable counter, reads it inside the
// same transaction as the operation, and persists the advance strictly
// after the operation succeeds — so a failed upload cannot consume a use
// or a byte allowance.
func TestStatefulCaveats_DoNotAdvanceWhenTheOperationFails(t *testing.T) {
	t.Parallel()

	maxUses := caveat.MaxUses(1)
	exhausted := baseRequest(t, time.Now())
	exhausted.UsesBefore = 1
	for range 5 {
		checkFails(t, maxUses, exhausted)
	}

	maxBytes := caveat.MaxBytesTransferred(100)
	overBudget := baseRequest(t, time.Now())
	overBudget.BytesTransferredBefore = 50
	overBudget.ContentLength = 60
	for range 5 {
		checkFails(t, maxBytes, overBudget)
	}

	// And the same for the time-based stateful caveat: a first-use instant
	// already past the window stays past it, however many times it is read.
	firstUse := caveat.ExpiresAfterFirstUse(time.Hour)
	stale := baseRequest(t, time.Now())
	stale.FirstUsedAt = stale.Now.Add(-2 * time.Hour)
	for range 5 {
		checkFails(t, firstUse, stale)
	}
}

// TestStatefulCaveatKindsAreExactlyTheThreeThatNeedAReservation pins the
// partition the envelope's token types rest on. Adding a fourth stateful
// kind without widening this set — or quietly reclassifying one of these
// three as offline — is how a stateful caveat ends up on a token a third
// party is handed.
func TestStatefulCaveatKindsAreExactlyTheThreeThatNeedAReservation(t *testing.T) {
	t.Parallel()

	want := []string{"expires_after_first_use", "max_bytes_transferred", "max_uses"}
	got := slices.Clone(caveat.StatefulKinds())
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("StatefulKinds() = %v, want %v\n"+
			"a stateful caveat requires a counter read inside the operation's own transaction, "+
			"so it may only ever appear on a redemption token: see docs/wire-format.md", got, want)
	}

	for _, kind := range want {
		if !caveat.IsStatefulKind(kind) {
			t.Errorf("IsStatefulKind(%q) = false, want true", kind)
		}
	}
	for _, kind := range []string{"expires_at", "resource_scope", "client_cidr", "unknown"} {
		if caveat.IsStatefulKind(kind) {
			t.Errorf("IsStatefulKind(%q) = true, want false", kind)
		}
	}
}

func TestClientCIDR_IPv4AndIPv6AndMappedAddresses(t *testing.T) {
	t.Parallel()
	c := caveat.ClientCIDR(netip.MustParsePrefix("10.0.0.0/8"))

	req := baseRequest(t, time.Now())
	req.ClientIP = netip.MustParseAddr("10.1.2.3")
	checkOK(t, c, req)

	req.ClientIP = netip.MustParseAddr("192.168.1.1")
	checkFails(t, c, req)

	// An IPv4-mapped IPv6 address must match the same IPv4 prefix.
	req.ClientIP = netip.MustParseAddr("::ffff:10.1.2.3")
	checkOK(t, c, req)

	c6 := caveat.ClientCIDR(netip.MustParsePrefix("2001:db8::/32"))
	req.ClientIP = netip.MustParseAddr("2001:db8::1")
	checkOK(t, c6, req)
	req.ClientIP = netip.MustParseAddr("2001:db9::1")
	checkFails(t, c6, req)
}

// TestClientCIDR_RefusesAnUnsetClientAddress is new, and it is the same
// fail-open-by-forgotten-field hazard DelegationDepth's guard exists for: a
// zero netip.Addr is "nobody populated this", and netip.Prefix.Contains
// returns false for it, which happens to be the safe answer for a bounded
// prefix — but 0.0.0.0/0 contains nothing either, so the refusal must be
// explicit rather than incidental.
func TestClientCIDR_RefusesAnUnsetClientAddress(t *testing.T) {
	t.Parallel()

	req := baseRequest(t, time.Now())
	req.ClientIP = netip.Addr{}
	checkFails(t, caveat.ClientCIDR(netip.MustParsePrefix("10.0.0.0/8")), req)
	checkFails(t, caveat.ClientCIDR(netip.MustParsePrefix("0.0.0.0/0")), req)
}

func TestProcessorAudience_RejectsOtherProcessorThumbprint(t *testing.T) {
	t.Parallel()
	c := caveat.ProcessorAudience("thumbprint-A")

	req := baseRequest(t, time.Now())
	req.ProcessorIdentity = "thumbprint-A"
	checkOK(t, c, req)

	req.ProcessorIdentity = "thumbprint-B"
	checkFails(t, c, req)
}

func TestDelegationDepth_RejectsChainDeeperThanMax(t *testing.T) {
	t.Parallel()
	c := caveat.DelegationDepth(2)

	req := baseRequest(t, time.Now())
	req.ChainDepth = 2
	checkOK(t, c, req)

	req.ChainDepth = 3
	checkFails(t, c, req)
}

// TestDelegationDepth_RejectsUnpopulatedChainDepth is cas's I1 regression
// test: ChainDepth's documented minimum is 1 (a never-derived token still
// has a root link), so 0 is unambiguously "nobody populated this field" —
// not a legitimate depth-zero request — and must be refused the same as any
// other depth outside range, never silently treated as satisfying every
// DelegationDepth caveat.
//
// In this module the field is also populated by the verifier from the chain
// it just walked rather than by the caller, so the hazard is closed twice:
// see chain.Verify.
func TestDelegationDepth_RejectsUnpopulatedChainDepth(t *testing.T) {
	t.Parallel()
	c := caveat.DelegationDepth(2)

	req := baseRequest(t, time.Now())
	req.ChainDepth = 0
	checkFails(t, c, req)

	req.ChainDepth = -5
	checkFails(t, c, req)
}

func TestRequiredReadiness_RejectsAStateNotListed(t *testing.T) {
	t.Parallel()
	c := caveat.RequiredReadiness{"ready", "indexed"}

	req := baseRequest(t, time.Now())
	req.Readiness = "ready"
	checkOK(t, c, req)

	req.Readiness = "ingesting"
	checkFails(t, c, req)

	req.Readiness = "" // unpopulated
	checkFails(t, c, req)
}

func TestWatermark_RefusesOriginalThroughWatermarkedLink(t *testing.T) {
	t.Parallel()
	c := caveat.Watermark("renditions/watermarked")

	req := baseRequest(t, time.Now())
	req.Rendition = "renditions/watermarked"
	checkOK(t, c, req) // serving the watermarked rendition is fine

	original := req
	original.Rendition = ""    // the original content
	checkFails(t, c, original) // the gateway must refuse the original through this link
}

// unregisteredKindCaveat implements the public Caveat contract under a kind
// no decoder was ever registered for, to exercise CheckAll's own
// fail-closed check (as opposed to the codec's).
type unregisteredKindCaveat struct{}

func (unregisteredKindCaveat) Kind() string               { return "test.never_registered_for_checkall" }
func (unregisteredKindCaveat) Check(caveat.Request) error { return nil }
func (unregisteredKindCaveat) Narrows(caveat.Caveat) bool { return false }

// TestUnknownCaveatKind_FailsClosed is the invariant the charter calls a
// bypass if broken: a verifier that ignores what it does not understand.
func TestUnknownCaveatKind_FailsClosed(t *testing.T) {
	t.Parallel()

	g := testGrant(t, unregisteredKindCaveat{})
	if err := caveat.CheckAll([]caveat.Grant{g}, baseRequest(t, time.Now())); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("CheckAll() with an unregistered caveat kind error = %v, want wrapping ErrUnknownCaveat", err)
	}
}

// TestCheckAll_RejectsNilCaveatRatherThanPanicking is cas's I2 regression
// test: a nil entry in a grant's caveat list (from a bug constructing the
// slice, or a registered decoder returning a nil Caveat with a nil error)
// must be refused, not dereferenced — calling Kind() on a nil interface
// value panics, since there is no concrete type to dispatch to.
func TestCheckAll_RejectsNilCaveatRatherThanPanicking(t *testing.T) {
	t.Parallel()

	g := testGrant(t, nil)
	if err := caveat.CheckAll([]caveat.Grant{g}, baseRequest(t, time.Now())); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("CheckAll() with a nil caveat error = %v, want wrapping ErrUnknownCaveat", err)
	}
}

// TestCheckAll_RejectsEmptyChain is cas's round-2-of-5 regression test.
// Once checkGrantFields became the sole enforcement point for permissions,
// resources and the time bounds, iterating zero grants (nothing to fail)
// started vacuously granting any permission for any resource.
func TestCheckAll_RejectsEmptyChain(t *testing.T) {
	t.Parallel()

	req := baseRequest(t, time.Now())
	req.Permission = "doc.erase_content_everywhere"

	if err := caveat.CheckAll(nil, req); !errors.Is(err, caveat.ErrEmptyChain) {
		t.Errorf("CheckAll(nil, req) error = %v, want wrapping ErrEmptyChain", err)
	}
	if err := caveat.CheckAll([]caveat.Grant{}, req); !errors.Is(err, caveat.ErrEmptyChain) {
		t.Errorf("CheckAll([]Grant{}, req) error = %v, want wrapping ErrEmptyChain", err)
	}
}

func TestNarrows_RejectsWideningAttempts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	parentExpiry := caveat.ExpiresAt(now)
	if caveat.ExpiresAt(now.Add(time.Hour)).Narrows(parentExpiry) {
		t.Error("a later ExpiresAt must not narrow an earlier parent")
	}
	if !caveat.ExpiresAt(now.Add(-time.Hour)).Narrows(parentExpiry) {
		t.Error("an earlier ExpiresAt must narrow a later parent")
	}

	parentPerms := caveat.PermissionSet(domain.NewPermissionSet("doc.read_content"))
	widerPerms := caveat.PermissionSet(domain.NewPermissionSet("doc.read_content", "doc.write_content"))
	if widerPerms.Narrows(parentPerms) {
		t.Error("a larger permission set must not narrow a smaller parent")
	}
	if !parentPerms.Narrows(widerPerms) {
		t.Error("a subset permission set must narrow a superset parent")
	}

	parentCIDR := caveat.ClientCIDR(netip.MustParsePrefix("10.0.0.0/8"))
	if caveat.ClientCIDR(netip.MustParsePrefix("0.0.0.0/0")).Narrows(parentCIDR) {
		t.Error("a wider CIDR must not narrow a narrower parent")
	}
	if !caveat.ClientCIDR(netip.MustParsePrefix("10.1.0.0/16")).Narrows(parentCIDR) {
		t.Error("a narrower CIDR within the parent's range must narrow it")
	}
}

// narrowsTableCase is one row of TestNarrows_AllSixteenKindsBothDirections:
// parent is some caveat value, narrower must narrow it, and wider (when
// non-nil) must not. wider is nil for the two pure presence flags, whose
// only same-kind comparison is equality.
type narrowsTableCase struct {
	name     string
	parent   caveat.Caveat
	narrower caveat.Caveat
	wider    caveat.Caveat
}

func narrowsTable(t *testing.T) []narrowsTableCase {
	t.Helper()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	docScope := func(doc string) caveat.ResourceScope {
		return caveat.ResourceScope{Scopes: []domain.ResourcePath{
			path(t, seg("tenant", "tenant-1"), seg("document", doc)),
		}}
	}
	slotScope := caveat.ResourceScope{Scopes: []domain.ResourcePath{
		path(t, seg("tenant", "tenant-1"), seg("document", "doc-1"), seg("slot", "pages")),
	}}
	tenantScope := caveat.ResourceScope{Scopes: []domain.ResourcePath{path(t, seg("tenant", "tenant-1"))}}

	return []narrowsTableCase{
		{"ExpiresAt", caveat.ExpiresAt(now), caveat.ExpiresAt(now.Add(-time.Hour)), caveat.ExpiresAt(now.Add(time.Hour))},
		{"NotBefore", caveat.NotBefore(now), caveat.NotBefore(now.Add(time.Hour)), caveat.NotBefore(now.Add(-time.Hour))},
		{
			"ExpiresAfterFirstUse",
			caveat.ExpiresAfterFirstUse(2 * time.Hour),
			caveat.ExpiresAfterFirstUse(time.Hour),
			caveat.ExpiresAfterFirstUse(3 * time.Hour),
		},
		{"MaxUses", caveat.MaxUses(5), caveat.MaxUses(3), caveat.MaxUses(10)},
		{"ResourceScope", docScope("doc-1"), slotScope, tenantScope},
		{
			"PermissionSet",
			caveat.PermissionSet(domain.NewPermissionSet("doc.read_content", "doc.tag")),
			caveat.PermissionSet(domain.NewPermissionSet("doc.read_content")),
			caveat.PermissionSet(domain.NewPermissionSet("doc.read_content", "doc.tag", "doc.delete")),
		},
		{"MaxContentLength", caveat.MaxContentLength(1000), caveat.MaxContentLength(500), caveat.MaxContentLength(2000)},
		{
			"AllowedContentTypes",
			caveat.AllowedContentTypes{"application/pdf", "image/png"},
			caveat.AllowedContentTypes{"application/pdf"},
			caveat.AllowedContentTypes{"application/pdf", "image/png", "application/zip"},
		},
		{
			"MaxBytesTransferred",
			caveat.MaxBytesTransferred(1000),
			caveat.MaxBytesTransferred(500),
			caveat.MaxBytesTransferred(2000),
		},
		{
			"RequireAuthenticatedRecipient",
			caveat.RequireAuthenticatedRecipient{},
			caveat.RequireAuthenticatedRecipient{},
			nil, // a pure presence flag has no "wider than present" variant
		},
		{
			"RequiredReadiness",
			caveat.RequiredReadiness{"ready", "quarantined"},
			caveat.RequiredReadiness{"ready"},
			caveat.RequiredReadiness{"ready", "quarantined", "pending"},
		},
		{"RequireDeclaredDigest", caveat.RequireDeclaredDigest{}, caveat.RequireDeclaredDigest{}, nil},
		{
			"ClientCIDR",
			caveat.ClientCIDR(netip.MustParsePrefix("10.0.0.0/8")),
			caveat.ClientCIDR(netip.MustParsePrefix("10.1.0.0/16")),
			caveat.ClientCIDR(netip.MustParsePrefix("0.0.0.0/0")),
		},
		{"DelegationDepth", caveat.DelegationDepth(5), caveat.DelegationDepth(3), caveat.DelegationDepth(10)},
		{
			"ProcessorAudience",
			caveat.ProcessorAudience("thumbprint-A"),
			caveat.ProcessorAudience("thumbprint-A"), // exact match only
			caveat.ProcessorAudience("thumbprint-B"),
		},
		{
			"Watermark",
			caveat.Watermark("renditions/w1"),
			caveat.Watermark("renditions/w1"), // exact match only
			caveat.Watermark("renditions/w2"),
		},
	}
}

// TestNarrows_AllSixteenKindsBothDirections is cas's I4 table test: every
// one of the sixteen caveat kinds, both directions, not just the four kinds
// the earlier test happened to cover.
func TestNarrows_AllSixteenKindsBothDirections(t *testing.T) {
	t.Parallel()

	table := narrowsTable(t)
	if len(table) != 16 {
		t.Fatalf("narrowsTable() has %d entries, want 16 (one per caveat kind)", len(table))
	}
	if got := len(caveat.RegisteredKinds()); got != 16 {
		t.Fatalf("RegisteredKinds() has %d entries, want 16: a kind was added without a row in this table", got)
	}

	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.narrower.Narrows(tc.parent) {
				t.Errorf("%s: narrower.Narrows(parent) = false, want true", tc.name)
			}
			if tc.wider != nil && tc.wider.Narrows(tc.parent) {
				t.Errorf("%s: wider.Narrows(parent) = true, want false", tc.name)
			}
			if !tc.parent.Narrows(tc.parent) {
				t.Errorf("%s: a caveat must narrow itself (reflexive)", tc.name)
			}
		})
	}
}

// TestNarrows_CrossKindAlwaysRefuses is the other half of cas's I4:
// comparing two DIFFERENT caveat kinds must always refuse to narrow, which
// is exactly the shape of bug a careless type assertion in a future Narrows
// implementation introduces. 16x16 minus the 16 same-kind diagonal entries
// is 240 cross-kind pairs, all of which must return false in both
// directions.
func TestNarrows_CrossKindAlwaysRefuses(t *testing.T) {
	t.Parallel()

	table := narrowsTable(t)
	samples := make([]caveat.Caveat, len(table))
	for i, tc := range table {
		samples[i] = tc.parent
	}

	checked := 0
	for i, child := range samples {
		for j, parent := range samples {
			if i == j {
				continue
			}
			checked++
			if child.Narrows(parent) {
				t.Errorf("%T.Narrows(%T) = true, want false (cross-kind must always refuse)", child, parent)
			}
		}
	}
	if checked != 240 {
		t.Fatalf("checked %d cross-kind pairs, want 240 (16*16 - 16 same-kind diagonal entries)", checked)
	}
}

// TestCaveats_NeverLeakSecretValues is the canary the charter's error
// discipline requires: construct caveats around a sentinel value, force
// every Check failure path, and assert no returned error's text contains
// the sentinel. The rule is that a refusal names nothing — not the caveat,
// not a value from it, not a value from the request — because a verifier
// that explains why a request was refused hands an attacker a dimension to
// search along.
func TestCaveats_NeverLeakSecretValues(t *testing.T) {
	t.Parallel()

	const sentinel = "SENTINEL-thumbprint-7f3a9c"
	now := time.Now()

	cases := []struct {
		name string
		c    caveat.Caveat
		req  caveat.Request
	}{
		{"ProcessorAudience", caveat.ProcessorAudience(sentinel), func() caveat.Request {
			r := baseRequest(t, now)
			r.ProcessorIdentity = "someone-else"
			return r
		}()},
		{"AllowedContentTypes", caveat.AllowedContentTypes{sentinel}, baseRequest(t, now)},
		{"ResourceScope", caveat.ResourceScope{Scopes: []domain.ResourcePath{
			path(t, seg("tenant", sentinel), seg("document", "doc-x")),
		}}, baseRequest(t, now)},
		{"Watermark", caveat.Watermark(sentinel), baseRequest(t, now)},
		{"RequiredReadiness", caveat.RequiredReadiness{sentinel}, baseRequest(t, now)},
		{"ClientCIDR", caveat.ClientCIDR(netip.MustParsePrefix("203.0.113.0/24")), baseRequest(t, now)},
		{"MaxUses", caveat.MaxUses(0), baseRequest(t, now)},
		{"ExpiresAt", caveat.ExpiresAt(now.Add(-time.Hour)), baseRequest(t, now)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.c.Check(tc.req)
			if err == nil {
				t.Fatalf("expected Check() to fail for this case")
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Errorf("error %q contains the sentinel value", err.Error())
			}
			// Nor may it name the caveat kind, which is itself a dimension
			// to search along.
			if strings.Contains(err.Error(), tc.c.Kind()) {
				t.Errorf("error %q names the caveat kind %q", err.Error(), tc.c.Kind())
			}
		})
	}
}

// TestCheckAllErrors_NeverNameTheFailingDimension extends the canary to
// CheckAll, where a composite failure could reassemble the oracle the
// per-caveat errors avoid.
func TestCheckAllErrors_NeverNameTheFailingDimension(t *testing.T) {
	t.Parallel()

	const sentinel = "SENTINEL-tenant-5b1e"
	g := caveat.Grant{
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{path(t, seg("tenant", sentinel))},
		Caveats:     []caveat.Caveat{caveat.ProcessorAudience(sentinel)},
	}

	err := caveat.CheckAll([]caveat.Grant{g}, baseRequest(t, time.Now()))
	if err == nil {
		t.Fatal("expected CheckAll() to fail")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("error %q contains the sentinel value", err.Error())
	}
}
