package captokentest

// This file holds the key-custody half of the contract, and it is the half
// the whole truncation argument rests on.
//
// captoken has no seal and no proof. A presented chain is powerless when
// truncated for two reasons that compose: every proper prefix ends in a
// delegation link, which authorises no operation, and deriving a new
// terminal link from an ancestor requires the signing key that ancestor
// bound in its cnf claim — which a downstream holder never received,
// because NO PRIVATE KEY IS EVER PART OF A TOKEN'S SERIALIZED FORM.
//
// The second half of that is an empirical claim about bytes, and until now
// nothing a consumer could call checked it. The predecessor's own test for
// it was one of the three key-handling properties CAS lost when it adopted
// this module: the counterparts live in internal/chain, which no consumer
// can import.
//
// So testKeyCustody checks the presentation against every encoding a
// private key takes in a rendering Go actually produces — raw, hex in both
// cases, base64 in all four alphabets, and the escaped forms — using the
// same needle set redaction.go uses for a secret in a log line. It checks
// the SEED as well as the full private key, because an Ed25519 private key
// is seed||public and the public half is legitimately in the token: a
// needle over the 64-byte key alone would pass against a token that had
// serialized the seed.

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/laenenai/captoken"
)

// testKeyCustody is the property above, plus the refusals that make a
// holder key the only thing that can extend a chain.
func testKeyCustody(t *testing.T, w Wiring, h *harness) {
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if root.HolderKey == nil {
		t.Fatal("Mint(a delegation token) returned no holder key; nothing could ever derive from it")
	}
	leaf, err := h.deriver.Derive(root.Token, root.HolderKey, h.leafSpec(w))
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}
	if leaf.HolderKey != nil {
		t.Error("Derive(a terminal token) returned a holder key; a terminal token cannot be derived " +
			"from, so there is no key to hold")
	}

	t.Run("no private key is anywhere in the presentation", func(t *testing.T) {
		// Both halves of the chain's key custody: the root key, which
		// signs root links, and the holder key the root bound for its
		// child. Each is checked as the full private key and as its seed,
		// because an Ed25519 private key is seed||public and the public
		// half is legitimately present in the cnf claim — a needle over
		// the 64 bytes alone would miss a token that serialized the 32
		// that matter.
		for name, key := range map[string]ed25519.PrivateKey{
			"the root signing key": h.rootKey,
			"the holder key":       root.HolderKey,
		} {
			for what, material := range map[string][]byte{
				"as the whole private key": key,
				"as its seed":              key.Seed(),
			} {
				for _, n := range leakNeedles(material) {
					if n.contained(leaf.Token) {
						t.Errorf("the presentation contains %s %s (%s); a recipient of these bytes "+
							"could then derive from the chain, and truncation would stop being powerless",
							name, what, n.what)
					}
				}
			}
		}
	})

	t.Run("deriving needs the key the parent bound", func(t *testing.T) {
		other, err := captoken.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		short := make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)
		copy(short, root.HolderKey)

		for name, key := range map[string]ed25519.PrivateKey{
			"a key the parent never bound": other.Private,
			"no key at all":                nil,
			"a truncated key":              short,
			// The public half of the very key the parent bound, which is
			// exactly what a recipient of the bytes holds: it is in the cnf
			// claim of the parent link. It must not be usable as a signing
			// key, or the custody argument would be about nothing.
			"the bound key's own public half": ed25519.PrivateKey(boundPublicKey(t, root.HolderKey)),
		} {
			if _, err := h.deriver.Derive(root.Token, key, h.leafSpec(w)); !errors.Is(err, captoken.ErrInvalidToken) {
				t.Errorf("Derive(with %s) error = %v, want wrapping ErrInvalidToken", name, err)
			}
		}
	})

	t.Run("a malformed key is refused at construction", func(t *testing.T) {
		short := make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)
		for name, key := range map[string]ed25519.PrivateKey{
			"no root key":          nil,
			"a truncated root key": short,
		} {
			if _, err := captoken.NewMinter(captoken.MinterConfig{
				Issuer: suiteIssuer, RootKey: key, Schema: w.Schema, Clock: h.clock,
			}); err == nil {
				t.Errorf("NewMinter(%s) error = nil, want a refusal", name)
			}
		}
		for name, keys := range map[string][]ed25519.PublicKey{
			"no trusted root keys":         nil,
			"a truncated trusted root key": {make(ed25519.PublicKey, ed25519.PublicKeySize-1)},
		} {
			if _, err := captoken.NewVerifier(captoken.VerifierConfig{
				Issuer: suiteIssuer, RootKeys: keys, Audience: suiteGateway,
				Schema: w.Schema, Clock: h.clock,
			}); err == nil {
				t.Errorf("NewVerifier(%s) error = nil, want a refusal", name)
			}
		}
	})
}

// boundPublicKey is the public half a parent link bound, which is what a
// holder of the bytes alone possesses.
func boundPublicKey(t *testing.T, key ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("an Ed25519 private key's public half is %T", key.Public())
	}
	return pub
}
