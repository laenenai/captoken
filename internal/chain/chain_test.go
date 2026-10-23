package chain

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/captoken/internal/caveat"
	"github.com/laenenai/captoken/internal/domain"
	"github.com/laenenai/captoken/internal/reserve"
)

// TestFormatConstantsArePinned fixes every constant that enters signed or
// authenticated bytes as a literal.
//
// This is not decoration. On 2026-10-23 a textual module rename in audit
// rewrote a hash function's domain tag, which is a cryptographic input to
// every entry digest, and local verification missed it because `go test`
// served cached results. The lesson recorded there is that a constant
// entering signed bytes needs a test asserting its literal, so the failure
// says "the format changed" instead of leaving a reader to work backwards
// from two values that no longer match.
//
// Every constant below is reachable by a find-and-replace over a module
// path, a package name or an organisation name, which is exactly how such a
// rename arrives:
//
//   - MediaType contains the product name.
//   - Prefix contains an abbreviation of it.
//   - Algorithm, the JWK key type and curve are JOSE registry values, which
//     a well-meaning rename of a local identifier could still catch.
//   - The claim names are the format, and a Go field rename that forgot its
//     struct tag would change them silently.
//
// Updating this test to make a build green is the one thing never to do
// with it. A change to any of these is a wire-format change: it needs a new
// FormatVersion and a new committed vector, together.
func TestFormatConstantsArePinned(t *testing.T) {
	t.Parallel()

	if FormatVersion != 1 {
		t.Errorf("FormatVersion = %d, want 1", FormatVersion)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"MediaType", MediaType, "captoken+jwt"},
		{"Algorithm", Algorithm, "EdDSA"},
		{"Prefix", Prefix, "ct1"},
		{"Separator", Separator, "~"},
		{"jwkKeyTypeOKP", jwkKeyTypeOKP, "OKP"},
		{"jwkCurveEd25519", jwkCurveEd25519, "Ed25519"},
		{"jwkThumbprintTmpl", jwkThumbprintTmpl, `{"crv":"%s","kty":"%s","x":"%s"}`},
		{"TypeDelegation", string(TypeDelegation), "delegation"},
		{"TypeExecution", string(TypeExecution), "execution"},
		{"TypeRedemption", string(TypeRedemption), "redemption"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q\n"+
				"this constant is an input to signed bytes: changing it changes what every "+
				"issued token says. See docs/wire-format.md.", tc.name, tc.got, tc.want)
		}
	}
}

// TestClaimNamesArePinned asserts the claim set's member names AND their
// order, by marshalling a fully populated claim set and comparing the
// resulting member sequence against the published format.
//
// The order is part of the format because the claim set is signed bytes: it
// comes from the claims struct's field declaration order, which a reorder
// during an ordinary refactor would change without any other test
// noticing.
func TestClaimNamesArePinned(t *testing.T) {
	t.Parallel()

	nbf := int64(1000)
	jwk, err := encodeJWK(make(ed25519.PublicKey, ed25519.PublicKeySize))
	if err != nil {
		t.Fatalf("encodeJWK() error = %v", err)
	}
	raw, err := json.Marshal(claims{
		Version: 1, Type: "delegation", Issuer: "i", Subject: "s",
		Audience: []string{"a"}, TokenID: "j", ChainID: "c",
		IssuedAt: 1, NotBefore: &nbf, ExpiresAt: 2,
		Permissions: []string{"p"}, Resources: [][][]string{{{"tenant", "t"}}},
		Caveats:      []caveat.WireCaveat{{Kind: "max_uses", Value: json.RawMessage(`1`)}},
		Confirmation: &confirmation{JWK: jwk},
		ParentHash:   "h",
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	want := `{"ctv":1,"ctt":"delegation","iss":"i","sub":"s","aud":["a"],"jti":"j","cid":"c",` +
		`"iat":1,"nbf":1000,"exp":2,"prm":["p"],"res":[[["tenant","t"]]],` +
		`"cav":[{"k":"max_uses","v":1}],` +
		`"cnf":{"jwk":{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},` +
		`"par_hash":"h"}`
	if string(raw) != want {
		t.Fatalf("claim set encodes as\n  %s\nwant\n  %s\n"+
			"the member names AND their order are the wire format: see docs/wire-format.md", raw, want)
	}
}

// TestHeaderIsExactlyAlgAndTyp pins the protected header's bytes. go-jose
// serializes it from a map, so the member order is lexicographic; the
// format document states that rule rather than this literal, but the
// literal is what catches the day the library changes its mind.
func TestHeaderIsExactlyAlgAndTyp(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	compact, err := signLink(claims{Version: FormatVersion}, key.Private)
	if err != nil {
		t.Fatalf("signLink() error = %v", err)
	}
	segment, _, _ := strings.Cut(compact, ".")
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	const want = `{"alg":"EdDSA","typ":"captoken+jwt"}`
	if string(raw) != want {
		t.Fatalf("protected header = %s, want %s", raw, want)
	}
}

// TestVerify_RefusesEveryMalformedPresentation covers the shapes that are
// not a chain at all. Each must be refused before any signature is checked,
// and none may be interpreted as a near-miss of something valid.
func TestVerify_RefusesEveryMalformedPresentation(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	v := f.verifier(t, weakened{}, nil)
	leaf := f.tokens[2]

	cases := map[string]string{
		"empty":                            "",
		"no prefix":                        strings.Join(f.tokens, Separator),
		"a foreign prefix":                 "cas1." + leaf,
		"the prefix alone":                 Prefix,
		"the prefix and a separator":       Prefix + Separator,
		"a bare JWT":                       leaf,
		"a JSON-serialized JWS":            present([]string{`{"payload":"e30","signatures":[]}`}),
		"a detached payload":               present([]string{"aaa..bbb"}),
		"an unprotected header":            present([]string{"aaa.bbb.ccc.ddd"}),
		"garbage":                          present([]string{"not-a-jws"}),
		"a chain longer than MaxLinks":     present(make([]string, DefaultMaxLinks+1)),
		"a link whose header is not JSON":  present([]string{base64.RawURLEncoding.EncodeToString([]byte("x")) + ".e30.c2ln"}),
		"a link with an empty header":      present([]string{".e30.c2ln"}),
		"a link with an empty payload":     present([]string{strings.SplitN(leaf, ".", 2)[0] + "..c2ln"}),
		"a chain with an empty final link": present(append(append([]string(nil), f.tokens...), "")),
	}
	for name, presented := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := v.Verify(context.Background(), presented, f.request(t)); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Verify(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}
}

// TestVerify_RefusesTheAlgorithmConfusionFamily attacks key and algorithm
// selection directly: every one of these is a token asking the verifier to
// decide how, or with what, to check it.
func TestVerify_RefusesTheAlgorithmConfusionFamily(t *testing.T) {
	t.Parallel()
	f := honestChain(t)

	// A header with each hostile shape, over the honest root link's payload
	// and signature. None may be read, let alone acted on.
	_, payloadAndSig, _ := strings.Cut(f.tokens[0], ".")
	headers := map[string]string{
		"alg none":                  `{"alg":"none","typ":"captoken+jwt"}`,
		"alg HS256":                 `{"alg":"HS256","typ":"captoken+jwt"}`,
		"alg EdDSA with a kid":      `{"alg":"EdDSA","typ":"captoken+jwt","kid":"anything"}`,
		"alg EdDSA with a jwk":      `{"alg":"EdDSA","typ":"captoken+jwt","jwk":{"kty":"OKP"}}`,
		"alg EdDSA with a jku":      `{"alg":"EdDSA","typ":"captoken+jwt","jku":"https://attacker/"}`,
		"alg EdDSA with a crit":     `{"alg":"EdDSA","typ":"captoken+jwt","crit":["x"]}`,
		"a plain JWT typ":           `{"alg":"EdDSA","typ":"JWT"}`,
		"no typ at all":             `{"alg":"EdDSA"}`,
		"alg named twice":           `{"alg":"none","alg":"EdDSA","typ":"captoken+jwt"}`,
		"alg as an array":           `{"alg":["EdDSA"],"typ":"captoken+jwt"}`,
		"a header that is an array": `["EdDSA"]`,
	}
	for name, h := range headers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			forged := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + payloadAndSig
			presented := present(append([]string{forged}, f.tokens[1:]...))
			if _, err := f.verifier(t, weakened{}, nil).Verify(
				context.Background(), presented, f.request(t),
			); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Verify(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}
}

// TestVerify_RefusesAClaimSetNamingAMemberTwice is RFC 8725's duplicate
// rule, which no mainstream library enforces. encoding/json keeps the last
// duplicate and other implementations keep the first, so a token whose
// meaning depends on which library reads it must be refused by all of them.
func TestVerify_RefusesAClaimSetNamingAMemberTwice(t *testing.T) {
	t.Parallel()
	f := honestChain(t)

	raw, err := json.Marshal(f.claims[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Inject a second "ctt", naming a type that would change everything.
	doubled := strings.Replace(string(raw), `"ctt":"delegation"`, `"ctt":"execution","ctt":"delegation"`, 1)
	if doubled == string(raw) {
		t.Fatal("test bug: the claim set did not contain the member being doubled")
	}

	header, _, _ := strings.Cut(f.tokens[0], ".")
	forged := header + "." + base64.RawURLEncoding.EncodeToString([]byte(doubled)) + ".c2ln"
	presented := present(append([]string{forged}, f.tokens[1:]...))

	if _, err := f.verifier(t, weakened{}, nil).Verify(
		context.Background(), presented, f.request(t),
	); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify(a claim set naming ctt twice) error = %v, want wrapping ErrInvalidToken", err)
	}
}

// TestVerify_RefusesAnUnknownClaim is the fail-closed reading of a
// versioned format: a build that meets a member it does not know does not
// implement the token's format, and evaluating the part it recognized would
// be exactly the silent-acceptance failure the charter rules out.
func TestVerify_RefusesAnUnknownClaim(t *testing.T) {
	t.Parallel()
	f := honestChain(t)

	raw, err := json.Marshal(f.claims[2])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	extended := `{"xyz":1,` + strings.TrimPrefix(string(raw), "{")
	header, _, _ := strings.Cut(f.tokens[2], ".")
	forged := header + "." + base64.RawURLEncoding.EncodeToString([]byte(extended)) + ".c2ln"

	if _, err := f.verifier(t, weakened{}, nil).Verify(
		context.Background(), present([]string{f.tokens[0], f.tokens[1], forged}), f.request(t),
	); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify(a claim set with an unknown member) error = %v, want wrapping ErrInvalidToken", err)
	}
}

// TestVerify_RefusesAForeignRootKey is the point of public-key
// verification: a chain rooted somewhere else is not this issuer's chain.
func TestVerify_RefusesAForeignRootKey(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	other, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	v, err := NewVerifier(VerifierConfig{
		Issuer:   testIssuer,
		RootKeys: []ed25519.PublicKey{other.Public},
		Audience: testAudience,
		Schema:   f.schema,
		Clock:    f.clock,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, err := v.Verify(context.Background(), present(f.tokens), f.request(t)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify(under a foreign root key) error = %v, want wrapping ErrInvalidToken", err)
	}
}

// TestVerify_TriesEveryTrustedRootKey pins the rotation property, and the
// discipline it rests on: the token carries nothing that selects a key, so
// every trusted key is tried rather than one being looked up.
func TestVerify_TriesEveryTrustedRootKey(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	retired, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	for _, keys := range [][]ed25519.PublicKey{
		{retired.Public, f.rootPub},
		{f.rootPub, retired.Public},
	} {
		v, nerr := NewVerifier(VerifierConfig{
			Issuer: testIssuer, RootKeys: keys, Audience: testAudience,
			Schema: f.schema, Clock: f.clock,
		})
		if nerr != nil {
			t.Fatalf("NewVerifier() error = %v", nerr)
		}
		if _, verr := v.Verify(context.Background(), present(f.tokens), f.request(t)); verr != nil {
			t.Errorf("Verify() with the correct key in the set error = %v, want nil", verr)
		}
	}
}

// TestVerify_RefusesARequestTheChainDoesNotPermit separates the two
// outcomes a caller must be able to tell apart: an invalid credential, and
// a valid credential that does not permit this request.
func TestVerify_RefusesARequestTheChainDoesNotPermit(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	v := f.verifier(t, weakened{}, nil)

	cases := map[string]func(req *caveat.Request){
		"a permission the chain never granted": func(req *caveat.Request) { req.Permission = "doc.write_content" },
		"a resource outside the leaf's scope": func(req *caveat.Request) {
			req.Resource = testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d2"))
		},
		"an address outside the leaf's CIDR": func(req *caveat.Request) {
			req.ClientIP = mustAddr(t, "10.9.9.9")
		},
		"a body larger than the leaf allows": func(req *caveat.Request) { req.ContentLength = 1 << 20 },
		"an unknown body length":             func(req *caveat.Request) { req.ContentLength = -1 },
		"after the leaf's expiry":            func(req *caveat.Request) { req.Now = testNow.Add(2 * time.Hour) },
		"before the leaf's start":            func(req *caveat.Request) { req.Now = testNow.Add(-2 * time.Hour) },
		"an unvalidated resource path":       func(req *caveat.Request) { req.Resource = domain.ResourcePath{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := f.request(t)
			mutate(&req)
			_, err := v.Verify(context.Background(), present(f.tokens), req)
			if !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
				t.Errorf("Verify(%s) error = %v, want wrapping ErrCaveatNotSatisfied", name, err)
			}
			if errors.Is(err, ErrInvalidToken) {
				t.Errorf("Verify(%s) reported an invalid token; the token is valid and the request is not permitted", name)
			}
		})
	}
}

// TestVerify_ErrorsNameNothing is the module's error-discipline canary at
// its outermost boundary. Every refusal path is forced with a sentinel
// value embedded in the token and in the request, and no returned error may
// contain it — nor a link index, nor a claim name, nor a caveat kind.
func TestVerify_ErrorsNameNothing(t *testing.T) {
	t.Parallel()

	const sentinel = "SENTINEL-tenant-9f4c2a"
	schema := testSchema(t)
	clock := domain.NewFixedClock(testNow)
	rootKey, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	minter, err := NewMinter(MinterConfig{
		Issuer: sentinel, RootKey: rootKey.Private, Schema: schema, Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}
	scope, err := schema.Path(seg("tenant", sentinel))
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	minted, err := minter.Mint(MintSpec{
		Type:        TypeExecution,
		Subject:     sentinel,
		Audience:    []domain.Audience{sentinel},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet(domain.Permission(sentinel)),
		Resources:   []domain.ResourcePath{scope},
		Caveats:     []caveat.Caveat{caveat.ProcessorAudience(sentinel)},
	})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	v, err := NewVerifier(VerifierConfig{
		Issuer: "someone-else", RootKeys: []ed25519.PublicKey{rootKey.Public},
		Audience: "someone-else", Schema: schema, Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	req := caveat.Request{Now: testNow, Permission: domain.Permission(sentinel), Resource: scope}
	_, verr := v.Verify(context.Background(), minted.Token, req)
	if verr == nil {
		t.Fatal("expected Verify() to refuse")
	}
	// The refusal is the bare sentinel: no value from the token, no value
	// from the request, no caveat kind, and no indication of WHICH check
	// failed — see sanitize.
	if verr.Error() != ErrInvalidToken.Error() {
		t.Errorf("Verify() error = %q, want exactly %q: a refusal names nothing",
			verr.Error(), ErrInvalidToken.Error())
	}
	for _, forbidden := range []string{sentinel, "processor_audience", "issuer", "audience"} {
		if strings.Contains(verr.Error(), forbidden) {
			t.Errorf("error %q contains %q, which a refusal must never name", verr.Error(), forbidden)
		}
	}
}

// ---- the partition, end to end ------------------------------------------

// TestRedemptionToken_IsRefusedByAThirdPartyOnAudienceAlone is the
// charter's central claim about the partition, demonstrated.
//
// A redemption token carries the stateful caveats and names the issuer's
// reservation service as its audience. A third-party verifier refuses it on
// "aud" — a claim RFC 7519 requires be checked and which every mainstream
// JWT library checks correctly — so it never has to know that stateful
// caveats exist, and cannot be tricked into accepting one it could not
// evaluate. That is what makes a naive-but-correct verification SOUND
// rather than merely usually right, with no dependence on "crit".
func TestRedemptionToken_IsRefusedByAThirdPartyOnAudienceAlone(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	deriver, err := NewDeriver(DeriverConfig{Schema: f.schema, Clock: f.clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}

	redemption, err := deriver.Derive(present(f.tokens[:2]), f.keys[2], MintSpec{
		Type:        TypeRedemption,
		Subject:     "holder-3",
		Audience:    []domain.Audience{reserveAud},
		NotBefore:   testNow,
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources: []domain.ResourcePath{
			testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
		},
		Caveats: []caveat.Caveat{
			caveat.MaxContentLength(1 << 10),
			caveat.DelegationDepth(3),
			caveat.ClientCIDR(mustPrefix(t, "10.1.2.0/24")),
			caveat.MaxUses(2),
		},
	})
	if err != nil {
		t.Fatalf("Derive(redemption) error = %v", err)
	}

	// The third party: a gateway whose own audience is not the reservation
	// service. It refuses, and it refuses for the audience, not because it
	// recognized max_uses.
	thirdParty := f.verifier(t, weakened{}, nil)
	if _, err := thirdParty.Verify(context.Background(), redemption.Token, f.request(t)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a third party accepted a redemption token: error = %v, want wrapping ErrInvalidToken", err)
	}

	// The issuer's own verifier, which IS the reservation service, accepts
	// it and reads the counters from the port.
	counters := reserve.NewMemory()
	issuerSide, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{f.rootPub}, Audience: reserveAud,
		Schema: f.schema, Clock: f.clock, Reservations: counters,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	verified, err := issuerSide.Verify(context.Background(), redemption.Token, f.request(t))
	if err != nil {
		t.Fatalf("the reservation service refused a redemption token: %v", err)
	}
	if verified.Type != TypeRedemption {
		t.Errorf("Type = %q, want %q", verified.Type, TypeRedemption)
	}
}

// TestRedemptionToken_IsRefusedWithoutAReservationService is the
// fail-closed half: a verifier that cannot supply the counters refuses
// rather than skipping the check, so ignorance and refusal are the same
// outcome and the worst case of a partial verifier is a refused request.
func TestRedemptionToken_IsRefusedWithoutAReservationService(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	token := f.redemptionToken(t, caveat.MaxUses(2))

	for name, counters := range map[string]reserve.Counters{
		"none wired up":         nil,
		"the stubbed transport": reserve.Stub{},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, err := NewVerifier(VerifierConfig{
				Issuer: testIssuer, RootKeys: []ed25519.PublicKey{f.rootPub}, Audience: reserveAud,
				Schema: f.schema, Clock: f.clock, Reservations: counters,
			})
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			if _, err := v.Verify(context.Background(), token, f.request(t)); !errors.Is(err, reserve.ErrNoReservationService) {
				t.Errorf("Verify() error = %v, want wrapping ErrNoReservationService", err)
			}
		})
	}
}

// TestStatefulCaveats_ReadTheCounterAndNeverAdvanceIt is the ordering
// discipline at the envelope's boundary. Verification reads the counters
// and never writes them, so a failed operation cannot consume a use: the
// advance is the caller's, after the operation, inside the same
// transaction.
func TestStatefulCaveats_ReadTheCounterAndNeverAdvanceIt(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	token := f.redemptionToken(t, caveat.MaxUses(2))

	counters := reserve.NewMemory()
	v, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{f.rootPub}, Audience: reserveAud,
		Schema: f.schema, Clock: f.clock, Reservations: counters,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	// Many verifications, none of which advances anything.
	for range 5 {
		if _, err := v.Verify(context.Background(), token, f.request(t)); err != nil {
			t.Fatalf("Verify() error = %v, want nil", err)
		}
	}
	for chain, snapshot := range counters.Snapshot() {
		t.Errorf("verification advanced the counters for %q to %+v; it must only read them", chain, snapshot)
	}

	// Once the caller records two successful operations, the third is
	// refused — and refused as a request the token does not permit, not as
	// an invalid token.
	verified, err := v.Verify(context.Background(), token, f.request(t))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	for range 2 {
		if err := counters.Advance(context.Background(), verified.ChainID, reserve.Advance{Uses: 1}); err != nil {
			t.Fatalf("Advance() error = %v", err)
		}
	}
	if _, err := v.Verify(context.Background(), token, f.request(t)); !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Errorf("Verify() after the allowance was spent error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

// TestRevocation_OfTheAncestorKillsEveryDescendant is the property the
// Biscuit spike found Biscuit getting for free and recommended this design
// should too. The revocation identifier is the root link's token id, which
// every descendant carries verbatim, so one record kills the chain with no
// enumeration of descendants.
func TestRevocation_OfTheAncestorKillsEveryDescendant(t *testing.T) {
	t.Parallel()
	f := honestChain(t)

	revocations := reserve.NewMemory()
	v, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{f.rootPub}, Audience: testAudience,
		Schema: f.schema, Clock: f.clock, Revocations: revocations,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	verified, err := v.Verify(context.Background(), present(f.tokens), f.request(t))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	// The identifier is the ROOT's token id, not the leaf's, and it is the
	// same bytes in every link.
	if string(verified.ChainID) != f.claims[0].TokenID {
		t.Fatalf("ChainID = %q, want the root's jti %q", verified.ChainID, f.claims[0].TokenID)
	}

	if err := revocations.Revoke(context.Background(), verified.ChainID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	// Every prefix and the whole chain are now dead, from one record.
	if _, err := v.Verify(context.Background(), present(f.tokens), f.request(t)); !errors.Is(err, reserve.ErrRevoked) {
		t.Errorf("Verify() after revoking the ancestor error = %v, want wrapping ErrRevoked", err)
	}
}

// ---- derivation ----------------------------------------------------------

// TestDerive_RefusesAWideningBeforeSigningIt covers the early check. It is
// a courtesy rather than the guarantee — the verifier re-checks every link
// on every verification — but a minting path that signs a token nothing
// will ever accept is a bug worth catching at the minter.
func TestDerive_RefusesAWideningBeforeSigningIt(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	deriver, err := NewDeriver(DeriverConfig{Schema: f.schema, Clock: f.clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}
	parent := present(f.tokens[:2])

	base := MintSpec{
		Type:        TypeExecution,
		Subject:     "holder-3",
		Audience:    []domain.Audience{testAudience},
		NotBefore:   testNow,
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources: []domain.ResourcePath{
			testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
		},
		Caveats: []caveat.Caveat{
			caveat.MaxContentLength(1 << 10),
			caveat.DelegationDepth(3),
			caveat.ClientCIDR(mustPrefix(t, "10.1.2.0/24")),
		},
	}
	if _, err := deriver.Derive(parent, f.keys[2], base); err != nil {
		t.Fatalf("Derive(a narrowing spec) error = %v, want nil", err)
	}

	cases := map[string]func(s *MintSpec){
		"a permission the parent never granted": func(s *MintSpec) {
			s.Permissions = domain.NewPermissionSet("doc.read_content", "doc.delete")
		},
		"a wider resource scope": func(s *MintSpec) {
			s.Resources = []domain.ResourcePath{testPath(t, seg("tenant", "t1"))}
		},
		"a later expiry":   func(s *MintSpec) { s.ExpiresAt = testNow.Add(99 * time.Hour) },
		"an earlier start": func(s *MintSpec) { s.NotBefore = testNow.Add(-time.Hour) },
		"a raised ceiling": func(s *MintSpec) {
			s.Caveats = []caveat.Caveat{
				caveat.MaxContentLength(1 << 30),
				caveat.DelegationDepth(3),
				caveat.ClientCIDR(mustPrefix(t, "10.1.2.0/24")),
			}
		},
		"a dropped caveat": func(s *MintSpec) {
			s.Caveats = []caveat.Caveat{caveat.MaxContentLength(1 << 10), caveat.DelegationDepth(3)}
		},
		"a widened audience": func(s *MintSpec) {
			s.Audience = []domain.Audience{testAudience, "elsewhere"}
		},
		"a stateful caveat on an execution token": func(s *MintSpec) {
			s.Caveats = append(s.Caveats, caveat.MaxUses(1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			spec := base
			spec.Caveats = append([]caveat.Caveat(nil), base.Caveats...)
			mutate(&spec)
			if _, err := deriver.Derive(parent, f.keys[2], spec); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Derive(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}
}

// TestDerive_RefusesTheWrongKeyAndANonDelegatingParent pins the two
// structural preconditions: the holder must hold the key the parent bound,
// and only a delegation token authorises derivation at all.
func TestDerive_RefusesTheWrongKeyAndANonDelegatingParent(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	deriver, err := NewDeriver(DeriverConfig{Schema: f.schema, Clock: f.clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}
	spec := MintSpec{
		Type: TypeExecution, Subject: "x", Audience: []domain.Audience{testAudience},
		NotBefore: testNow, ExpiresAt: testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources: []domain.ResourcePath{
			testPath(t, seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
		},
		Caveats: []caveat.Caveat{
			caveat.MaxContentLength(1 << 10),
			caveat.DelegationDepth(3),
			caveat.ClientCIDR(mustPrefix(t, "10.1.2.0/24")),
		},
	}

	// The wrong key: the root's own, or a fresh one.
	for name, key := range map[string]ed25519.PrivateKey{
		"a key the parent never bound": f.keys[1],
		"no key at all":                nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := deriver.Derive(present(f.tokens[:2]), key, spec); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Derive(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}

	// A terminal parent: an execution token binds no key, so nothing can be
	// derived from it. This is the other half of why truncation is
	// powerless — a chain cannot be extended past its terminal link either.
	t.Run("a terminal parent", func(t *testing.T) {
		t.Parallel()
		if _, err := deriver.Derive(present(f.tokens), f.keys[2], spec); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Derive(from an execution token) error = %v, want wrapping ErrInvalidToken", err)
		}
	})
}

// TestMint_RefusesAnIncompleteSpec covers the mint-time validation, whose
// job is that nothing malformed is ever signed — which is what makes the
// decoder's "well formed by construction" premise true.
func TestMint_RefusesAnIncompleteSpec(t *testing.T) {
	t.Parallel()
	schema := testSchema(t)
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	minter, err := NewMinter(MinterConfig{
		Issuer: testIssuer, RootKey: key.Private, Schema: schema, Clock: domain.NewFixedClock(testNow),
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}

	good := MintSpec{
		Type: TypeExecution, Subject: "s", Audience: []domain.Audience{testAudience},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{testPath(t, seg("tenant", "t1"))},
	}
	if _, err := minter.Mint(good); err != nil {
		t.Fatalf("Mint(a complete spec) error = %v", err)
	}

	cases := map[string]func(s *MintSpec){
		"an unknown type":                 func(s *MintSpec) { s.Type = "whatever" },
		"no expiry":                       func(s *MintSpec) { s.ExpiresAt = time.Time{} },
		"no permission":                   func(s *MintSpec) { s.Permissions = nil },
		"no resource":                     func(s *MintSpec) { s.Resources = nil },
		"an unvalidated resource path":    func(s *MintSpec) { s.Resources = []domain.ResourcePath{{}} },
		"no audience on a terminal token": func(s *MintSpec) { s.Audience = nil },
		"an empty validity window":        func(s *MintSpec) { s.NotBefore = s.ExpiresAt },
		"a nil caveat":                    func(s *MintSpec) { s.Caveats = []caveat.Caveat{nil} },
		"a stateful caveat on an execution token": func(s *MintSpec) {
			s.Caveats = []caveat.Caveat{caveat.MaxUses(1)}
		},
		"two caveats of one kind": func(s *MintSpec) {
			s.Caveats = []caveat.Caveat{caveat.MaxUses(1), caveat.MaxUses(2)}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			spec := good
			mutate(&spec)
			if _, err := minter.Mint(spec); err == nil {
				t.Errorf("Mint(%s) error = nil, want a refusal", name)
			}
		})
	}
}

func TestNewVerifierAndMinter_RefuseAnIncompleteConfig(t *testing.T) {
	t.Parallel()
	schema := testSchema(t)
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if _, err := NewMinter(MinterConfig{RootKey: key.Private, Schema: schema}); err == nil {
		t.Error("NewMinter() with no issuer error = nil, want a refusal")
	}
	if _, err := NewMinter(MinterConfig{Issuer: testIssuer, Schema: schema}); err == nil {
		t.Error("NewMinter() with no root key error = nil, want a refusal")
	}
	if _, err := NewMinter(MinterConfig{Issuer: testIssuer, RootKey: key.Private}); err == nil {
		t.Error("NewMinter() with no schema error = nil, want a refusal")
	}

	base := VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{key.Public},
		Audience: testAudience, Schema: schema,
	}
	for name, mutate := range map[string]func(c *VerifierConfig){
		"no issuer":             func(c *VerifierConfig) { c.Issuer = "" },
		"no audience":           func(c *VerifierConfig) { c.Audience = "" },
		"no root keys":          func(c *VerifierConfig) { c.RootKeys = nil },
		"a short root key":      func(c *VerifierConfig) { c.RootKeys = []ed25519.PublicKey{{1, 2, 3}} },
		"no schema":             func(c *VerifierConfig) { c.Schema = domain.ResourceSchema{} },
		"a negative MaxLinks":   func(c *VerifierConfig) { c.MaxLinks = -1 },
		"an unbounded MaxLinks": func(c *VerifierConfig) { c.MaxLinks = MaxMaxLinks + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := base
			mutate(&cfg)
			if _, err := NewVerifier(cfg); err == nil {
				t.Errorf("NewVerifier(%s) error = nil, want a refusal", name)
			}
		})
	}
}

// TestThumbprint_MatchesRFC7638 checks the one key identifier this module
// computes against the RFC's own worked shape: SHA-256 over the required
// members in lexicographic order, no whitespace, base64url unpadded.
func TestThumbprint_MatchesRFC7638(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	got, err := thumbprint(key.Public)
	if err != nil {
		t.Fatalf("thumbprint() error = %v", err)
	}
	if len(got) != 43 { // 32 bytes, base64url unpadded
		t.Errorf("thumbprint = %q, want 43 base64url characters", got)
	}
	if _, err := thumbprint(ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Error("thumbprint(a short key) error = nil, want a refusal")
	}
}

func TestDecodeJWK_RefusesAnythingButAnEd25519OKPKey(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"an octet key":        `{"kty":"oct","crv":"Ed25519","x":"AAAA"}`,
		"a different curve":   `{"kty":"OKP","crv":"X25519","x":"AAAA"}`,
		"a short key":         `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"an extra member":     `{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"secret"}`,
		"a duplicated member": `{"kty":"oct","kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"not base64url":       `{"kty":"OKP","crv":"Ed25519","x":"!!!"}`,
		"not an object":       `["OKP"]`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeJWK(json.RawMessage(raw)); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("decodeJWK(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}
}
