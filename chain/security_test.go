package chain

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
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
