package captoken_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/laenenai/captoken"
	"github.com/laenenai/captoken/captokentest"
)

// TestKeyHoldingTypesNeverDiscloseTheirMaterial holds every type in this
// module's public surface that carries an Ed25519 private key or a presentation
// token to CONVENTIONS.md's "Rendering a secret" convention.
//
// The root signing key is the most valuable secret this module touches: it
// authorises every chain the deployment will ever mint, and unlike a DEK it
// cannot be rotated without re-minting. Before this test existed, %+v on a
// *Minter printed it in full — the key was in an unexported field, and fmt
// cannot call a method on a value it reaches through one, so no amount of
// redaction on a key type would have helped. That is why the methods are on the
// holding types rather than on a wrapper.
//
// The presentation token is covered as material too, because a capability token
// is a bearer credential: a token in a log is an authorisation someone else can
// replay until it expires.
func TestKeyHoldingTypesNeverDiscloseTheirMaterial(t *testing.T) {
	t.Parallel()

	// A fixed reader, so the material this test searches for is known rather
	// than random — a random key could in principle contain a byte sequence
	// that makes a containment check pass for the wrong reason.
	kp, err := captoken.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0xA7}, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	key := []byte(kp.Private)

	schema, err := captoken.NewResourceSchema(captoken.SegmentKind{Name: "tenant"})
	if err != nil {
		t.Fatalf("NewResourceSchema() error = %v", err)
	}

	cfg := captoken.MinterConfig{Issuer: "issuer-01HQ", RootKey: kp.Private, Schema: schema}
	minter, err := captoken.NewMinter(cfg)
	if err != nil {
		t.Fatalf("NewMinter() error = %v", err)
	}

	const presentation = "eyJhbGciOiJFZERTQSJ9.e30.c2lnbmF0dXJlLXdoaWNoLWlzLWEtYmVhcmVyLWNyZWRlbnRpYWw"

	for _, c := range []struct {
		name     string
		v        any
		material []byte
	}{
		{"KeyPair", kp, key},
		{"MinterConfig", cfg, key},
		{"Minter", minter, key},
		{"MinterValue", *minter, key},
		{"MintedHolderKey", captoken.Minted{Token: presentation, HolderKey: kp.Private}, key},
		{"MintedToken", captoken.Minted{Token: presentation, HolderKey: kp.Private}, []byte(presentation)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			captokentest.NoSecretLeaksInAnyRendering(t, c.v, c.material)
		})
	}
}
