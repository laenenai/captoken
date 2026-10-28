package chain

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
	"github.com/laenenai/captoken/reserve"
)

// opaqueSigner hides ed25519.PrivateKey's concrete type, forcing the
// crypto.Signer path through go-jose's opaque adapter.
type opaqueSigner struct{ crypto.Signer }

func TestMinter_AcceptsCryptoSignerRoot(t *testing.T) {
	t.Parallel()
	schema := testSchema(t)
	root, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	clock := domain.NewFixedClock(testNow)
	minter, err := NewMinter(MinterConfig{
		Issuer: testIssuer, RootKey: opaqueSigner{root.Private}, Schema: schema, Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}
	holder, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	minted, err := minter.Mint(MintSpec{
		Type:            TypeDelegation,
		Subject:         "holder",
		Audience:        []domain.Audience{testAudience},
		ExpiresAt:       testNow.Add(time.Hour),
		Permissions:     domain.NewPermissionSet("doc.read_content"),
		Resources:       []domain.ResourcePath{testPath(t, seg("tenant", "t1"))},
		HolderPublicKey: holder.Public,
	})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if minted.HolderKey != nil {
		t.Fatal("Mint() returned a generated holder key despite HolderPublicKey being set")
	}
	verifier, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{root.Public},
		Audience: testAudience, Schema: schema, Clock: clock, NoRevocation: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, err := verifier.Verify(context.Background(), minted.Token, caveat.Request{
		Permission: "doc.read_content", Resource: testPath(t, seg("tenant", "t1")),
	}); !errors.Is(err, ErrNotAuthorizing) {
		t.Fatalf("Verify() error = %v, want ErrNotAuthorizing after the opaque signature checks", err)
	}
}

func TestHolderSuppliedKey_DerivesWithCryptoSigner(t *testing.T) {
	t.Parallel()
	schema := testSchema(t)
	root, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	holder, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	clock := domain.NewFixedClock(testNow)
	minter, err := NewMinter(MinterConfig{
		Issuer: testIssuer, RootKey: root.Private, Schema: schema, Clock: clock,
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}
	rootToken, err := minter.Mint(MintSpec{
		Type:            TypeDelegation,
		Subject:         "holder",
		Audience:        []domain.Audience{testAudience},
		ExpiresAt:       testNow.Add(time.Hour),
		Permissions:     domain.NewPermissionSet("doc.read_content"),
		Resources:       []domain.ResourcePath{testPath(t, seg("tenant", "t1"))},
		HolderPublicKey: holder.Public,
	})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	deriver, err := NewDeriver(DeriverConfig{Schema: schema, Clock: clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}
	leaf, err := deriver.Derive(rootToken.Token, opaqueSigner{holder.Private}, MintSpec{
		Type:        TypeExecution,
		Subject:     "holder",
		Audience:    []domain.Audience{testAudience},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{testPath(t, seg("tenant", "t1"))},
	})
	if err != nil {
		t.Fatalf("Derive(with a crypto.Signer) error = %v", err)
	}
	verifier, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{root.Public},
		Audience: testAudience, Schema: schema, Clock: clock, NoRevocation: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	verified, err := verifier.Verify(context.Background(), leaf.Token, caveat.Request{
		Permission: "doc.read_content", Resource: testPath(t, seg("tenant", "t1")),
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(verified.TerminalResources) != 1 {
		t.Errorf("TerminalResources = %v, want one path", verified.TerminalResources)
	}
}

func TestValidatePublicKey_RejectsSmallOrder(t *testing.T) {
	t.Parallel()
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	if err := validatePublicKey(identity); err == nil {
		t.Fatal("validatePublicKey(identity) error = nil, want a refusal")
	}
	if _, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{identity},
		Audience: testAudience, Schema: testSchema(t), NoRevocation: true,
	}); err == nil {
		t.Fatal("NewVerifier(identity root key) error = nil, want a refusal")
	}
}

func TestNewVerifier_RequiresRevocationDecision(t *testing.T) {
	t.Parallel()
	schema := testSchema(t)
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	cfg := VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{key.Public},
		Audience: testAudience, Schema: schema,
	}
	if _, err := NewVerifier(cfg); !errors.Is(err, ErrNoRevocationBackend) {
		t.Fatalf("NewVerifier(no revocation backend) error = %v, want wrapping ErrNoRevocationBackend", err)
	}
	cfg.NoRevocation = true
	if _, err := NewVerifier(cfg); err != nil {
		t.Fatalf("NewVerifier(explicit NoRevocation) error = %v", err)
	}
	cfg.Revocations = reserve.NewMemory()
	if _, err := NewVerifier(cfg); !errors.Is(err, ErrNoRevocationBackend) {
		t.Fatalf("NewVerifier(Revocations and NoRevocation) error = %v, want wrapping ErrNoRevocationBackend", err)
	}
}

type leakingRevocations struct{}

func (leakingRevocations) IsRevoked(context.Context, domain.RevocationID) (bool, error) {
	return false, errors.New("postgres://user:secret@db.example/captoken")
}

func (leakingRevocations) Revoke(context.Context, domain.RevocationID) error { return nil }

func TestVerify_BackendErrorsAreOpaque(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	v, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{f.rootPub},
		Audience: testAudience, Schema: f.schema, Clock: f.clock,
		Revocations: leakingRevocations{},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	_, err = v.Verify(context.Background(), present(f.tokens), f.request(t))
	if !errors.Is(err, ErrBackend) {
		t.Fatalf("Verify() error = %v, want wrapping ErrBackend", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres") {
		t.Fatalf("Verify() leaked backend detail: %v", err)
	}
}

func TestCheckAll_RejectsZeroNow(t *testing.T) {
	t.Parallel()
	err := caveat.CheckAll([]caveat.Grant{{}}, caveat.Request{})
	if !errors.Is(err, caveat.ErrCaveatNotSatisfied) {
		t.Fatalf("CheckAll(zero Now) error = %v, want wrapping ErrCaveatNotSatisfied", err)
	}
}

func TestParseClaims_RejectsNonCanonicalEncoding(t *testing.T) {
	t.Parallel()

	invalidUTF8 := []byte("{\"sub\":\"\xff\"}")
	claimsSegment := base64.RawURLEncoding.EncodeToString(invalidUTF8)
	if _, err := parseClaims("x." + claimsSegment + ".y"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("parseClaims(invalid UTF-8) error = %v, want wrapping ErrInvalidToken", err)
	}

	reordered := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"s","ctv":1}`))
	if _, err := parseClaims("x." + reordered + ".y"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("parseClaims(reordered members) error = %v, want wrapping ErrInvalidToken", err)
	}

	spaced := base64.RawURLEncoding.EncodeToString([]byte(`{"ctv": 1}`))
	if _, err := parseClaims("x." + spaced + ".y"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("parseClaims(non-canonical whitespace) error = %v, want wrapping ErrInvalidToken", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"captoken+jwt","alg":"EdDSA"}`))
	if err := parseHeader(header + ".e30.sig"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("parseHeader(reordered members) error = %v, want wrapping ErrInvalidToken", err)
	}
}

func TestSplitPresentation_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	oversized := Prefix + Separator + strings.Repeat("a", MaxPresentationBytes)
	if _, err := splitPresentation(oversized, DefaultMaxLinks); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("splitPresentation(oversized) error = %v, want wrapping ErrInvalidToken", err)
	}
}

func TestZeroValuesFailClosed(t *testing.T) {
	t.Parallel()
	var minter Minter
	if _, err := minter.Mint(MintSpec{}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("zero Minter.Mint() error = %v, want wrapping ErrInvalidToken", err)
	}
	var deriver Deriver
	if _, err := deriver.Derive("ct1~x", nil, MintSpec{}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("zero Deriver.Derive() error = %v, want wrapping ErrInvalidToken", err)
	}
	var verifier Verifier
	if _, err := verifier.Verify(context.Background(), "ct1~x", caveat.Request{}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("zero Verifier.Verify() error = %v, want wrapping ErrInvalidToken", err)
	}
}

func TestConstructorsRejectTypedNilClock(t *testing.T) {
	t.Parallel()
	var clock *domain.FixedClock
	schema := testSchema(t)
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if _, err := NewMinter(MinterConfig{
		Issuer: testIssuer, RootKey: key.Private, Schema: schema, Clock: clock,
	}); err == nil {
		t.Fatal("NewMinter(typed-nil clock) error = nil, want a refusal")
	}
	if _, err := NewDeriver(DeriverConfig{Schema: schema, Clock: clock}); err == nil {
		t.Fatal("NewDeriver(typed-nil clock) error = nil, want a refusal")
	}
	if _, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{key.Public},
		Audience: testAudience, Schema: schema, Clock: clock, NoRevocation: true,
	}); err == nil {
		t.Fatal("NewVerifier(typed-nil clock) error = nil, want a refusal")
	}
}

func TestMintAndDerive_RefusePresentationsOverLimit(t *testing.T) {
	t.Parallel()
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
	large := largeDocumentPaths(t, schema, 255)
	if _, err := minter.Mint(MintSpec{
		Type:        TypeDelegation,
		Subject:     "alice",
		Audience:    []domain.Audience{testAudience},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   large,
	}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Mint(oversized presentation) error = %v, want wrapping ErrInvalidToken", err)
	}

	rootPaths := largeDocumentPaths(t, schema, 90)
	root, err := minter.Mint(MintSpec{
		Type:        TypeDelegation,
		Subject:     "alice",
		Audience:    []domain.Audience{testAudience},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   rootPaths,
	})
	if err != nil {
		t.Fatalf("Mint(a root under the limit) error = %v", err)
	}
	deriver, err := NewDeriver(DeriverConfig{Schema: schema, Clock: clock})
	if err != nil {
		t.Fatalf("NewDeriver() error = %v", err)
	}
	if _, err := deriver.Derive(root.Token, root.HolderKey, MintSpec{
		Type:        TypeExecution,
		Subject:     "alice",
		Audience:    []domain.Audience{testAudience},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   rootPaths,
	}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Derive(oversized presentation) error = %v, want wrapping ErrInvalidToken", err)
	}
}

func largeDocumentPaths(t *testing.T, schema domain.ResourceSchema, n int) []domain.ResourcePath {
	t.Helper()
	tenant := domain.Segment{Kind: "tenant", ID: "t1"}
	paths := make([]domain.ResourcePath, 0, n+1)
	base, err := schema.Path(tenant)
	if err != nil {
		t.Fatalf("Path(tenant) error = %v", err)
	}
	paths = append(paths, base)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%03d%s", i, strings.Repeat("x", 252))
		p, err := schema.Path(tenant, domain.Segment{Kind: "document", ID: id})
		if err != nil {
			t.Fatalf("Path(document) error = %v", err)
		}
		paths = append(paths, p)
	}
	return paths
}

func TestVerify_RejectsNonCanonicalSignatureEncodings(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	v := f.verifier(t, weakened{}, nil)
	parts, err := splitPresentation(present(f.tokens), DefaultMaxLinks)
	if err != nil {
		t.Fatalf("splitPresentation() error = %v", err)
	}

	mutate := func(link string, change func(string) string) string {
		segments := strings.Split(link, ".")
		segments[2] = change(segments[2])
		return strings.Join(segments, ".")
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	padBits := func(sig string) string {
		last := sig[len(sig)-1]
		index := strings.IndexByte(alphabet, last)
		if index < 0 || index+1 >= len(alphabet) {
			t.Fatalf("cannot mutate signature pad bits for %q", sig)
		}
		return sig[:len(sig)-1] + string(alphabet[index+1])
	}

	cases := map[string]func(string) string{
		"non-zero trailing pad bits": padBits,
		"embedded whitespace":        func(sig string) string { return sig[:10] + " " + sig[10:] },
		"leading whitespace":         func(sig string) string { return " " + sig },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			mutated := append([]string(nil), parts...)
			mutated[len(mutated)-1] = mutate(mutated[len(mutated)-1], change)
			if _, err := v.Verify(context.Background(), present(mutated), f.request(t)); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Verify(%s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		})
	}
}

func TestMint_DoesNotHTMLEscapeOpaqueLabels(t *testing.T) {
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
	minted, err := minter.Mint(MintSpec{
		Type:        TypeDelegation,
		Subject:     "a<b&c",
		Audience:    []domain.Audience{testAudience},
		ExpiresAt:   testNow.Add(time.Hour),
		Permissions: domain.NewPermissionSet("doc.read_content"),
		Resources:   []domain.ResourcePath{testPath(t, seg("tenant", "t1"))},
	})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	parts := strings.Split(strings.TrimPrefix(minted.Token, Prefix+Separator), Separator)
	segments := strings.Split(parts[0], ".")
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("DecodeString(payload) error = %v", err)
	}
	if !strings.Contains(string(payload), `"sub":"a<b&c"`) {
		t.Fatalf("payload escaped an opaque label: %s", payload)
	}
}

func TestConstructorErrorsAreNotCredentialErrors(t *testing.T) {
	t.Parallel()
	schema := testSchema(t)
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	var nilClock *domain.FixedClock
	cases := map[string]error{
		"nil root key": func() error {
			_, err := NewMinter(MinterConfig{Issuer: testIssuer, Schema: schema})
			return err
		}(),
		"typed-nil clock": func() error {
			_, err := NewDeriver(DeriverConfig{Schema: schema, Clock: nilClock})
			return err
		}(),
		"out-of-range max links": func() error {
			_, err := NewDeriver(DeriverConfig{Schema: schema, MaxLinks: MaxMaxLinks + 1})
			return err
		}(),
		"missing revocation decision": func() error {
			_, err := NewVerifier(VerifierConfig{
				Issuer: testIssuer, RootKeys: []ed25519.PublicKey{key.Public},
				Audience: testAudience, Schema: schema,
			})
			return err
		}(),
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error = %v, want wrapping ErrInvalidConfig", err)
			}
			if errors.Is(err, ErrInvalidToken) {
				t.Errorf("error = %v, must not wrap ErrInvalidToken", err)
			}
		})
	}
}

type canceledRevocations struct{}

func (canceledRevocations) IsRevoked(context.Context, domain.RevocationID) (bool, error) {
	return false, context.Canceled
}

func (canceledRevocations) Revoke(context.Context, domain.RevocationID) error { return nil }

func TestVerify_PreservesContextCancellation(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	v, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, RootKeys: []ed25519.PublicKey{f.rootPub},
		Audience: testAudience, Schema: f.schema, Clock: f.clock,
		Revocations: canceledRevocations{},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if _, err := v.Verify(context.Background(), present(f.tokens), f.request(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() error = %v, want context.Canceled", err)
	}
}

func TestRootPublicKey_ReturnsACopy(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	minter, err := NewMinter(MinterConfig{
		Issuer: testIssuer, RootKey: key.Private, Schema: testSchema(t),
	})
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}
	pub := minter.RootPublicKey()
	if pub == nil {
		t.Fatal("RootPublicKey() = nil")
	}
	pub[0] ^= 0xff
	if got := minter.RootPublicKey(); got[0] == pub[0] {
		t.Fatal("RootPublicKey() returned an aliased buffer")
	}
}

func TestGrantFrom_RequiresIssueTime(t *testing.T) {
	t.Parallel()
	_, err := grantFrom(claims{
		Issuer: "issuer-1", Subject: "alice", TokenID: "id-1", ChainID: "id-1",
		ExpiresAt:   1,
		Permissions: []string{"doc.read_content"},
		Resources:   [][][]string{{{"tenant", "t1"}}},
	}, testSchema(t))
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("grantFrom(missing iat) error = %v, want wrapping ErrInvalidToken", err)
	}
}

func TestParseClaims_RejectsNullOptionalMembers(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"ctv":1,"ctt":"delegation","iss":"i","sub":"s","jti":"j","cid":"j","iat":1,"nbf":null,"exp":2,"prm":["p"],"res":[[["tenant","t1"]]]}`)
	segment := base64.RawURLEncoding.EncodeToString(payload)
	if _, err := parseClaims("x." + segment + ".y"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("parseClaims(null nbf) error = %v, want wrapping ErrInvalidToken", err)
	}
}

func TestVerify_RejectsARootParentHash(t *testing.T) {
	t.Parallel()
	f := honestChain(t)
	c := f.claims[0]
	hash := ""
	c.ParentHash = &hash
	root, err := signLink(c, f.keys[0])
	if err != nil {
		t.Fatalf("signLink() error = %v", err)
	}
	tokens := append([]string{root}, f.tokens[1:]...)
	if _, err := f.verifier(t, weakened{}, nil).Verify(context.Background(), present(tokens), f.request(t)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(a root with par_hash) error = %v, want wrapping ErrInvalidToken", err)
	}
}

func TestPublicKeyThumbprint_IsStableAndRejectsBadKeys(t *testing.T) {
	t.Parallel()
	first, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	second, err := GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	a, err := PublicKeyThumbprint(first.Public)
	if err != nil {
		t.Fatalf("PublicKeyThumbprint() error = %v", err)
	}
	b, err := PublicKeyThumbprint(first.Public)
	if err != nil || a != b {
		t.Fatalf("PublicKeyThumbprint() is not stable: %q, %q (err = %v)", a, b, err)
	}
	c, err := PublicKeyThumbprint(second.Public)
	if err != nil || a == c {
		t.Fatalf("PublicKeyThumbprint() collided: %q, %q (err = %v)", a, c, err)
	}
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	if _, err := PublicKeyThumbprint(identity); err == nil {
		t.Fatal("PublicKeyThumbprint(identity) error = nil, want a refusal")
	}
}
