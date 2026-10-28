package chain

// This is the adversarial suite for the module's central invariant:
//
//	No sequence of derivations can produce a token permitting more than its
//	ancestor.
//
// It is an internal test rather than an external one because an adversary
// is not restricted to the public API. The attacks below forge links
// directly — re-signing a chain's suffix with the keys a dishonest holder
// legitimately possesses — which is the realistic worst case and the one a
// test driven only through Mint and Derive cannot reach, since those refuse
// a widening before signing it.
//
// # The adversary model
//
// A dishonest holder at depth d holds the signing key the chain bound for
// link d, and every byte of every link. They can therefore rewrite link d
// and rebuild the whole suffix after it, choosing fresh keys for the links
// they mint. They cannot touch link d-1 or anything before it, because they
// never received those keys — no private key is ever part of a token's
// serialized form.
//
// rebuild below is exactly that adversary.
//
// # How this suite is kept honest
//
// TestSubsumption_SuiteHasTeeth deliberately breaks each guard in turn and
// asserts that the specific attack it is supposed to catch stops being
// caught. A suite of attacks that would all be refused anyway, by some
// other check, proves nothing about the check it names.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
	"github.com/laenenai/captoken/reserve"
)

// ---- fixtures -------------------------------------------------------------

const (
	testIssuer   = "issuer-1"
	testAudience = "gateway-1"
	reserveAud   = "captoken-reservations"
)

func testSchema(t *testing.T) domain.ResourceSchema {
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

func testPath(t *testing.T, segs ...domain.Segment) domain.ResourcePath {
	t.Helper()
	p, err := testSchema(t).Path(segs...)
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	return p
}

func seg(kind, id string) domain.Segment { return domain.Segment{Kind: kind, ID: id} }

func ptr[T any](v T) *T { return &v }

var testNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// fixture is an honestly minted chain plus the keys that signed it, so the
// adversary can rebuild any suffix of it.
type fixture struct {
	rootPub ed25519.PublicKey
	tokens  []string
	keys    []ed25519.PrivateKey
	claims  []claims
	clock   *domain.FixedClock
	schema  domain.ResourceSchema
}

// honestChain mints root(delegation) -> middle(delegation) -> leaf(execution)
// and records every key, which is what lets the attacks below rebuild a
// suffix the way a real holder could.
func honestChain(t *testing.T) fixture {
	t.Helper()
	schema := testSchema(t)
	clock := domain.NewFixedClock(testNow)

	rootKey, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	minter, err := NewMinter(MinterConfig{
		Issuer: testIssuer, RootKey: rootKey.Private, Schema: schema, Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}

	tenant := testPath(t, seg("tenant", "t1"))
	fileset := testPath(t, seg("tenant", "t1"), seg("fileset", "a"))
	doc := testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1"))

	root, err := minter.Mint(MintSpec{
		Type:        TypeDelegation,
		Subject:     "holder-1",
		Audience:    []domain.Audience{testAudience, reserveAud},
		ExpiresAt:   testNow.Add(24 * time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content", "doc.write_content", "doc.tag"),
		Resources:   []domain.ResourcePath{tenant},
		Caveats: []caveat.Caveat{
			caveat.MaxContentLength(1 << 20),
			caveat.DelegationDepth(4),
			caveat.ClientCIDR(netip.MustParsePrefix("10.0.0.0/8")),
		},
	})
	if err != nil {
		t.Fatalf("Mint(root) error = %v", err)
	}

	deriver, err := NewDeriver(DeriverConfig{Schema: schema, Clock: clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}

	middle, err := deriver.Derive(root.Token, root.HolderKey, MintSpec{
		Type:        TypeDelegation,
		Subject:     "holder-2",
		Audience:    []domain.Audience{testAudience, reserveAud},
		NotBefore:   testNow,
		ExpiresAt:   testNow.Add(12 * time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content", "doc.write_content"),
		Resources:   []domain.ResourcePath{fileset},
		Caveats: []caveat.Caveat{
			caveat.MaxContentLength(1 << 16),
			caveat.DelegationDepth(3),
			caveat.ClientCIDR(netip.MustParsePrefix("10.1.0.0/16")),
		},
	})
	if err != nil {
		t.Fatalf("Derive(middle) error = %v", err)
	}

	leaf, err := deriver.Derive(middle.Token, middle.HolderKey, MintSpec{
		Type:        TypeExecution,
		Subject:     "holder-3",
		Audience:    []domain.Audience{testAudience},
		NotBefore:   testNow,
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{doc},
		Caveats: []caveat.Caveat{
			caveat.MaxContentLength(1 << 10),
			caveat.DelegationDepth(3),
			caveat.ClientCIDR(netip.MustParsePrefix("10.1.2.0/24")),
		},
	})
	if err != nil {
		t.Fatalf("Derive(leaf) error = %v", err)
	}

	tokens, err := splitPresentation(leaf.Token, DefaultMaxLinks)
	if err != nil {
		t.Fatalf("splitPresentation() error = %v", err)
	}
	parsed := make([]claims, len(tokens))
	for i, tok := range tokens {
		c, perr := parseClaims(tok)
		if perr != nil {
			t.Fatalf("parseClaims(link %d) error = %v", i, perr)
		}
		parsed[i] = c
	}

	return fixture{
		rootPub: rootKey.Public,
		tokens:  tokens,
		keys:    []ed25519.PrivateKey{rootKey.Private, root.HolderKey, middle.HolderKey},
		claims:  parsed,
		clock:   clock,
		schema:  schema,
	}
}

// rebuild is the adversary: it applies mutate to link `from`'s claims and
// re-signs every link from there to the leaf, with the keys the chain
// legitimately bound for them, recomputing each par_hash as it goes. The
// result is the best forgery a holder at depth `from` can produce.
func (f fixture) rebuild(t *testing.T, from int, mutate func(*claims)) string {
	t.Helper()
	if from < 0 || from >= len(f.claims) {
		t.Fatalf("rebuild: from = %d, out of range for %d links", from, len(f.claims))
	}

	out := append([]string(nil), f.tokens[:from]...)
	cs := make([]claims, len(f.claims))
	copy(cs, f.claims)
	mutate(&cs[from])

	for i := from; i < len(cs); i++ {
		if i > 0 {
			cs[i].ParentHash = ptr(parentHash(signingInput(out[i-1])))
		}
		tok, err := signLink(cs[i], f.keys[i])
		if err != nil {
			t.Fatalf("signLink(link %d) error = %v", i, err)
		}
		out = append(out, tok)
	}
	return present(out)
}

// verifier returns a verifier for f, optionally weakened.
func (f fixture) verifier(t *testing.T, weak weakened, counters reserve.Counters) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierConfig{
		Issuer:       testIssuer,
		RootKeys:     []ed25519.PublicKey{f.rootPub},
		Audience:     testAudience,
		Schema:       f.schema,
		Clock:        f.clock,
		Reservations: counters,
		NoRevocation: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	v.weak = weak
	return v
}

func (f fixture) request(t *testing.T) caveat.Request {
	t.Helper()
	return caveat.Request{
		Now:           testNow,
		Permission:    "doc.read_content",
		Resource:      testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
		ClientIP:      netip.MustParseAddr("10.1.2.3"),
		ContentLength: 512,
		ContentType:   "application/pdf",
	}
}

// ---- the happy path, so the attacks are known to be attacking something --

func TestVerify_HonestChainAuthorizes(t *testing.T) {
	t.Parallel()
	f := honestChain(t)

	if _, err := f.verifier(t, weakened{}, nil).Verify(
		context.Background(), f.tokens[len(f.tokens)-1], f.request(t),
	); err == nil {
		t.Fatal("verifying only the leaf, without its ancestors, must fail: there is no chain to root it")
	}

	verified, err := f.verifier(t, weakened{}, nil).Verify(context.Background(), present(f.tokens), f.request(t))
	if err != nil {
		t.Fatalf("Verify(honest chain) error = %v, want nil", err)
	}
	if verified.Type != TypeExecution {
		t.Errorf("Type = %q, want %q", verified.Type, TypeExecution)
	}
	if verified.Depth != 3 {
		t.Errorf("Depth = %d, want 3", verified.Depth)
	}
	if got, want := string(verified.ChainID), f.claims[0].TokenID; got != want {
		t.Errorf("ChainID = %q, want the root link's token id %q", got, want)
	}
	// The chain identifier is byte-identical in every link, which is what
	// makes revoking the ancestor revoke every descendant.
	for i, c := range f.claims {
		if c.ChainID != f.claims[0].TokenID {
			t.Errorf("link %d: cid = %q, want the root's jti %q", i, c.ChainID, f.claims[0].TokenID)
		}
	}
	// The effective permission set is the intersection, which is the leaf's
	// here because every link narrowed.
	if len(verified.Permissions) != 1 || !verified.Permissions.Contains("doc.read_content") {
		t.Errorf("Permissions = %v, want exactly {doc.read_content}", verified.Permissions.Sorted())
	}
}

// ---- the adversarial suite ----------------------------------------------

// attack is one attempt to end up with more authority than an ancestor
// granted, or to present a chain that is not the chain it claims to be.
type attack struct {
	name  string
	build func(t *testing.T, f fixture) string
}

// attacks is the suite. Every entry must be refused with ErrInvalidToken.
func attacks() []attack {
	return []attack{
		{
			name: "add a permission the parent never granted",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) { addPermission(c, "doc.delete") })
			},
		},
		{
			name: "add a permission at the middle link, where the leaf still looks narrow",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 1, func(c *claims) { addPermission(c, "doc.erase_content_everywhere") })
			},
		},
		{
			name: "broaden a resource scope to the whole tenant",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					c.Resources = [][][]string{{{"tenant", "t1"}}}
				})
			},
		},
		{
			name: "step sideways into a sibling fileset whose id shares a prefix",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					c.Resources = [][][]string{{{"tenant", "t1"}, {"fileset", "ab"}, {"document", "d1"}}}
				})
			},
		},
		{
			name: "extend the expiry past the parent's",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					c.ExpiresAt = testNow.Add(48 * time.Hour).Unix()
				})
			},
		},
		{
			name: "move the start instant earlier than the parent's",
			build: func(t *testing.T, f fixture) string {
				start := testNow.Add(-time.Hour).Unix()
				return f.rebuild(t, 2, func(c *claims) { c.NotBefore = &start })
			},
		},
		{
			name: "raise a byte ceiling",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					setCaveat(t, c, "max_content_length", 1<<30)
				})
			},
		},
		{
			name: "widen a client CIDR",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					setCaveat(t, c, "client_cidr", "0.0.0.0/0")
				})
			},
		},
		{
			name: "raise the delegation depth bound",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					setCaveat(t, c, "delegation_depth", 99)
				})
			},
		},
		{
			name: "drop a caveat entirely",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					dropCaveat(c, "max_content_length")
				})
			},
		},
		{
			name: "drop every caveat",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) { c.Caveats = nil })
			},
		},
		{
			name: "re-order the chain",
			build: func(_ *testing.T, f fixture) string {
				return present([]string{f.tokens[0], f.tokens[2], f.tokens[1]})
			},
		},
		{
			name: "remove the middle link",
			build: func(_ *testing.T, f fixture) string {
				return present([]string{f.tokens[0], f.tokens[2]})
			},
		},
		{
			name: "replay a link twice in one chain",
			build: func(_ *testing.T, f fixture) string {
				return present([]string{f.tokens[0], f.tokens[1], f.tokens[1], f.tokens[2]})
			},
		},
		{
			name: "splice a link from another chain",
			build: func(t *testing.T, f fixture) string {
				other := honestChain(t)
				return present([]string{f.tokens[0], f.tokens[1], other.tokens[2]})
			},
		},
		{
			name: "forge a parent hash to make a spliced link fit",
			build: func(t *testing.T, f fixture) string {
				// Rewriting par_hash requires re-signing the link it is in,
				// and the adversary does not hold the key the parent bound
				// for it. Doing it anyway, with a key of their own, is the
				// strongest form of this attack.
				forgedKey, err := GenerateKey(nil)
				if err != nil {
					t.Fatalf("GenerateKey() error = %v", err)
				}
				c := f.claims[2]
				c.ParentHash = ptr(parentHash(signingInput(f.tokens[0])))
				tok, err := signLink(c, forgedKey.Private)
				if err != nil {
					t.Fatalf("signLink() error = %v", err)
				}
				return present([]string{f.tokens[0], tok})
			},
		},
		{
			name: "truncate the chain to a delegation prefix",
			build: func(_ *testing.T, f fixture) string {
				return present(f.tokens[:2])
			},
		},
		{
			name: "truncate the chain to the root alone",
			build: func(_ *testing.T, f fixture) string {
				return present(f.tokens[:1])
			},
		},
		{
			// The attack par_hash exists for. The cnf key chain already
			// defeats re-ordering, splicing and replay, because each link
			// must be signed by the key its parent named. It does not
			// defeat KEY REUSE: if one holder mints two siblings and binds
			// the same child key in both, a descendant of the narrow one
			// verifies cryptographically under the wide one too. par_hash
			// makes each link commit to exactly one parent's bytes, so a
			// party who holds the leaf's bytes but not its key cannot move
			// it to a parent it was not issued under.
			//
			// What this secures is the chain's PROVENANCE rather than an
			// extra bound on authority: because every link restates its
			// parent's caveats and verification intersects every link, the
			// terminal link already dominates. See mutation_test.go.
			name: "move a link to a wider sibling parent that reused the same child key",
			build: func(t *testing.T, f fixture) string {
				return present([]string{f.tokens[0], f.wideSibling(t), f.tokens[2]})
			},
		},
		{
			name: "rewrite the chain id to evade the ancestor's revocation",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) { c.ChainID = "not-the-ancestors-id" })
			},
		},
		{
			name: "change the issuer on a derived link",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) { c.Issuer = "issuer-2" })
			},
		},
		{
			name: "widen the audience beyond the parent's",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					// The middle link restricts nothing, so first narrow it
					// and then try to escape that restriction.
					c.Audience = []string{testAudience, "some-other-verifier"}
				})
			},
		},
		{
			name: "put a stateful caveat on an execution token",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					setCaveat(t, c, "max_uses", 1)
				})
			},
		},
		{
			// The placement rule from docs/wire-format.md: the four
			// dimensions carried as exp, nbf, prm and res are never cav
			// entries, and a verifier MUST refuse one that appears there.
			// This is the only way such a token can exist — Mint and Derive
			// both refuse to produce one — so it is an attack rather than a
			// round trip.
			//
			// What it buys is not an authority bound: the cav entry would
			// intersect with the standard claim, so a narrower one takes
			// effect and a wider one does not. It is an INTEROPERABILITY
			// forgery. A conforming verifier refuses the token outright and
			// a lenient one accepts it, so the same bytes authorise
			// different things at different gateways, which is the failure
			// the partition exists to prevent.
			name: "restate a standard claim as a caveat entry",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) {
					setCaveat(t, c, "expires_at", testNow.Add(30*time.Minute).Unix())
				})
			},
		},
		{
			name: "declare a format version this build does not know",
			build: func(t *testing.T, f fixture) string {
				return f.rebuild(t, 2, func(c *claims) { c.Version = FormatVersion + 1 })
			},
		},
	}
}

func TestSubsumption_Adversarial(t *testing.T) {
	t.Parallel()

	for _, a := range attacks() {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			f := honestChain(t)
			presented := a.build(t, f)

			_, err := f.verifier(t, weakened{}, nil).Verify(context.Background(), presented, f.request(t))
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify(%s) error = %v, want wrapping ErrInvalidToken", a.name, err)
			}
		})
	}
}

// ---- helpers the attacks use --------------------------------------------

// setCaveat replaces or inserts a caveat in c's caveat claim, keeping the
// claim in canonical (kind-sorted) order so the attack is refused for the
// reason it is testing and not for a malformed claim.
func setCaveat(t *testing.T, c *claims, kind string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal caveat value: %v", err)
	}
	for i := range c.Caveats {
		if c.Caveats[i].Kind == kind {
			c.Caveats[i].Value = raw
			return
		}
	}
	out := append([]caveat.WireCaveat(nil), c.Caveats...)
	out = append(out, caveat.WireCaveat{Kind: kind, Value: raw})
	for i := len(out) - 1; i > 0 && out[i-1].Kind > out[i].Kind; i-- {
		out[i-1], out[i] = out[i], out[i-1]
	}
	c.Caveats = out
}

// dropCaveat removes a caveat kind from c's caveat claim.
func dropCaveat(c *claims, kind string) {
	out := make([]caveat.WireCaveat, 0, len(c.Caveats))
	for _, entry := range c.Caveats {
		if entry.Kind != kind {
			out = append(out, entry)
		}
	}
	c.Caveats = out
}

// wideSibling returns a second, legitimately-derived middle link that
// reuses the SAME child key the honest middle link bound — the operational
// mistake par_hash exists to survive. It is signed by the key the root
// bound, so it is a token the holder at depth 1 could really have minted,
// and it is wider than the honest middle link while still narrowing the
// root.
func (f fixture) wideSibling(t *testing.T) string {
	t.Helper()

	id, err := domain.NewTokenID()
	if err != nil {
		t.Fatalf("NewTokenID() error = %v", err)
	}
	c := f.claims[1]
	c.TokenID = string(id)
	// As wide as the root allows, which is wider than the honest middle.
	c.Permissions = f.claims[0].Permissions
	c.Resources = f.claims[0].Resources
	c.ExpiresAt = f.claims[0].ExpiresAt
	c.Caveats = append([]caveat.WireCaveat(nil), f.claims[0].Caveats...)
	// The key reuse: keep the honest middle's cnf, so the honest leaf's
	// signing key fits under this link too.
	c.Confirmation = f.claims[1].Confirmation
	c.ParentHash = ptr(parentHash(signingInput(f.tokens[0])))

	tok, err := signLink(c, f.keys[1])
	if err != nil {
		t.Fatalf("signLink() error = %v", err)
	}
	return tok
}

// addPermission inserts p into c's permission claim, keeping the claim
// canonical (sorted, no duplicates). An attack that leaves the claim
// unsorted is refused for being malformed rather than for widening, which
// would make the suite pass for the wrong reason — the first version of
// this file had exactly that bug, and the mutation test found it.
func addPermission(c *claims, p string) {
	out := append([]string(nil), c.Permissions...)
	out = append(out, p)
	slices.Sort(out)
	c.Permissions = slices.Compact(out)
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q) error = %v", s, err)
	}
	return a
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q) error = %v", s, err)
	}
	return p
}

// redemptionToken derives a terminal redemption token from f's first two
// links, carrying the stateful caveats given. Its audience is the issuer's
// reservation service, which is what a third-party verifier refuses it on.
func (f fixture) redemptionToken(t *testing.T, stateful ...caveat.Caveat) string {
	t.Helper()
	deriver, err := NewDeriver(DeriverConfig{Schema: f.schema, Clock: f.clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}
	caveats := []caveat.Caveat{
		caveat.MaxContentLength(1 << 10),
		caveat.DelegationDepth(3),
		caveat.ClientCIDR(mustPrefix(t, "10.1.2.0/24")),
	}
	minted, err := deriver.Derive(present(f.tokens[:2]), f.keys[2], MintSpec{
		Type:        TypeRedemption,
		Subject:     "holder-3",
		Audience:    []domain.Audience{reserveAud},
		NotBefore:   testNow,
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources: []domain.ResourcePath{
			testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
		},
		Caveats: append(caveats, stateful...),
	})
	if err != nil {
		t.Fatalf("Derive(redemption) error = %v", err)
	}
	return minted.Token
}
