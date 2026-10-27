package captokentest

// This file is the canary for a refusal's ERROR, which is a different
// channel from a value's rendering and fails in a different way.
//
// redaction.go holds the rendering half: NoSecretLeaksInAnyRendering and
// RendersOnlyARedactionMarker hold a value to what it prints. Nothing there
// asserts anything about an error, and an error is the one string a caller
// is most likely to log verbatim, put in an HTTP response body, or attach to
// a trace span. The predecessor had exactly this canary
// (TestVerify_NeverLeaksKeyMaterialOrTokenBytes), and when CAS adopted this
// module its CI stopped running one, because the only counterpart lives in
// internal/chain.
//
// It is a separate file rather than an addition to redaction.go because
// redaction.go is a byte-identical copy shared across five modules. Editing
// it would diverge five copies to add something only this suite needs;
// adding beside it costs nothing.
//
// # The two halves, which are deliberately different assertions
//
// A VERIFIER's refusal must be the bare sentinel and nothing else. Not the
// check that failed, not the link index, not a claim, not a value: a
// verifier that explains which of a dozen checks a forgery failed has handed
// the forger a dimension to search along, and the search is cheap — flip one
// field, read the message, repeat. So the assertion for a verifier is
// equality against the sentinel's own text, which is stronger than any
// search for a secret: an error that is exactly "invalid token" cannot
// disclose anything.
//
// A MINTER's or DERIVER's refusal is allowed to explain itself, and does:
// "derivation would not narrow its parent", "holder key is not the key the
// parent bound". That is not an oversight. Those refusals happen on the
// ISSUER's or the HOLDER's own side of the trust boundary, where the caller
// already knows what it asked for, and a holder who cannot find out why
// their own derivation was refused cannot fix it. What must still hold there
// is the narrower property: an error that names a reason must not name
// MATERIAL. So the assertion for a minter is the needle search, over every
// encoding a key takes in a rendering Go produces.
//
// The needle set is redaction.go's, deliberately not a second one. An error
// is a string like any other, so the same encodings apply, and a second set
// written here would be a second thing to keep in step with a convention
// that already has one.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/captoken"
)

// refusalCase is one way a verifier refuses, reachable through the port.
type refusalCase struct {
	// want is the sentinel the refusal must be. ErrNotAuthorizing is the
	// one that is permitted to arrive wrapped, because it wraps
	// ErrInvalidToken by design — it says only that the presenter's own
	// terminal link is a delegation token, which the presenter chose.
	want error
	// build returns the verifier to ask, the presentation and the request.
	build func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request)
	// needs reports whether the consumer's wiring can express the case.
	needs func(w Wiring) bool
}

// refusalCases is every refusal a consumer can provoke through the port,
// paired with the sentinel it must be. A refusal path missing from here is a
// path whose discipline nothing checks.
func refusalCases() map[string]refusalCase {
	chainAndRequest := func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
		presented, _ := h.chain(t, w)
		return h.gateway, presented, h.request(w)
	}

	return map[string]refusalCase{
		"a resource the chain does not cover": {
			want: captoken.ErrCaveatNotSatisfied,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				v, presented, req := chainAndRequest(t, w, h)
				req.Resource = w.Sibling
				return v, presented, req
			},
		},
		"a permission the chain does not grant": {
			want: captoken.ErrCaveatNotSatisfied,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				v, presented, req := chainAndRequest(t, w, h)
				for _, p := range w.Wide.Sorted() {
					if !w.Narrow.Contains(p) {
						req.Permission = p
						break
					}
				}
				return v, presented, req
			},
		},
		"a request after the chain expired": {
			want: captoken.ErrCaveatNotSatisfied,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				v, presented, req := chainAndRequest(t, w, h)
				req.Now = suiteClock.Add(48 * time.Hour)
				return v, presented, req
			},
		},
		"a chain with trailing bytes": {
			want: captoken.ErrInvalidToken,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				v, presented, req := chainAndRequest(t, w, h)
				return v, presented + "tampered", req
			},
		},
		"a reordered chain": {
			want: captoken.ErrInvalidToken,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				presented, _ := h.chainOfThree(t, w)
				p := measurePresentation(t, h, w, presented, 3)
				return h.gateway, p.join([]string{p.links[0], p.links[2], p.links[1]}), h.request(w)
			},
		},
		"a string from an unrelated system": {
			want: captoken.ErrInvalidToken,
			build: func(_ *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				return h.gateway, "eyJhbGciOiJub25lIn0.e30.", h.request(w)
			},
		},
		"a chain under a foreign root key": {
			want: captoken.ErrInvalidToken,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
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
				return v, presented, h.request(w)
			},
		},
		"a chain truncated to a delegation prefix": {
			want: captoken.ErrNotAuthorizing,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				root, err := h.minter.Mint(h.rootSpec(w))
				if err != nil {
					t.Fatalf("Mint() error = %v", err)
				}
				return h.gateway, root.Token, h.request(w)
			},
		},
		"a redemption token at a verifier with no reservation service": {
			want: captoken.ErrNoReservationService,
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				presented := h.redemptionCarrying(t, w, captoken.MaxUses(1))
				v, err := captoken.NewVerifier(captoken.VerifierConfig{
					Issuer: suiteIssuer, RootKeys: []ed25519.PublicKey{h.rootPub},
					Audience: suiteReserver, Schema: w.Schema, Clock: h.clock,
				})
				if err != nil {
					t.Fatalf("NewVerifier() error = %v", err)
				}
				return v, presented, h.request(w)
			},
		},
		"a revoked chain": {
			want:  captoken.ErrRevoked,
			needs: func(w Wiring) bool { return w.Revocations != nil },
			build: func(t *testing.T, w Wiring, h *harness) (*captoken.Verifier, string, captoken.Request) {
				presented, _ := h.chain(t, w)
				verified, err := h.gateway.Verify(context.Background(), presented, h.request(w))
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				if err := w.Revocations.Revoke(context.Background(), verified.ChainID); err != nil {
					t.Fatalf("Revoke() error = %v", err)
				}
				return h.gateway, presented, h.request(w)
			},
		},
	}
}

// testEveryRefusalIsTheBareSentinel is the error discipline over every
// refusal a consumer can provoke. See this file's header comment for why
// equality against the sentinel's text is the assertion rather than a search
// for a secret.
func testEveryRefusalIsTheBareSentinel(t *testing.T, w Wiring, h *harness) {
	for name, tc := range refusalCases() {
		t.Run(name, func(t *testing.T) {
			if tc.needs != nil && !tc.needs(w) {
				t.Skip("the wiring does not supply the adapter this refusal needs")
			}
			v, presented, req := tc.build(t, w, h)

			_, err := v.Verify(context.Background(), presented, req)
			if err == nil {
				t.Fatal("Verify() accepted a request it must refuse, so this case checks nothing")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want wrapping %v", err, tc.want)
			}

			permitted := []string{
				tc.want.Error(),
				// ErrNotAuthorizing arrives wrapped in ErrInvalidToken
				// deliberately: from the presenter's point of view it is the
				// same refusal, and it is distinct only so an operator
				// reading their own logs can tell a truncated chain from a
				// forged one.
				captoken.ErrInvalidToken.Error() + ": " + tc.want.Error(),
			}
			if got := err.Error(); got != permitted[0] && got != permitted[1] {
				t.Errorf("the refusal reads %q, want exactly %q.\n"+
					"A verifier that says WHICH check a forgery failed has handed the forger a dimension "+
					"to search along: flip one field, read the message, repeat.", got, permitted[0])
			}
		})
	}
}

// testRefusalsDiscloseNoKeyMaterial is the needle half, over both sides of
// the trust boundary. A verifier's refusal is already pinned to the
// sentinel's text above, so this adds nothing there and is run anyway: it is
// the assertion that survives if the exactness rule is ever relaxed, and it
// is the only assertion covering the minter and the deriver, whose refusals
// are allowed to name a reason.
func testRefusalsDiscloseNoKeyMaterial(t *testing.T, w Wiring, h *harness) {
	root, err := h.minter.Mint(h.rootSpec(w))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	presented, _ := h.chain(t, w)

	// Every material a refusal could disclose, in the forms that matter:
	// the two private keys and their seeds, plus the presented bytes
	// themselves, which are a bearer credential — an error that quoted a
	// token into a log line has put a live credential in the log.
	materials := map[string][]byte{
		"the root signing key":  h.rootKey,
		"the root key's seed":   h.rootKey.Seed(),
		"the holder key":        root.HolderKey,
		"the holder key's seed": root.HolderKey.Seed(),
		"the presented chain":   []byte(presented),
		"the root link's bytes": []byte(root.Token),
	}

	// The issuer's and the holder's side, whose refusals explain themselves.
	//
	// The widening is attempted from the MIDDLE link, not from the root:
	// the root grants Wide, so a derivation from it that asks for Wide is
	// not a widening at all.
	middle, err := h.deriver.Derive(root.Token, root.HolderKey, h.middleSpec(w))
	if err != nil {
		t.Fatalf("Derive(the middle link) error = %v", err)
	}
	spec := h.leafSpec(w)
	spec.Permissions = w.Wide
	other, err := captoken.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	_, wideningErr := h.deriver.Derive(middle.Token, middle.HolderKey, spec)
	_, wrongKeyErr := h.deriver.Derive(root.Token, other.Private, h.leafSpec(w))
	_, terminalErr := h.deriver.Derive(presented, root.HolderKey, h.leafSpec(w))
	badSpec := h.leafSpec(w)
	badSpec.Resources = []captoken.ResourcePath{{}}
	_, mintErr := h.minter.Mint(badSpec)

	refusals := map[string]error{
		"Derive, widening its parent":                wideningErr,
		"Derive, with a key the parent did not bind": wrongKeyErr,
		"Derive, from a terminal link":               terminalErr,
		"Mint, with an unvalidated resource":         mintErr,
	}
	for name, rerr := range refusals {
		if rerr == nil {
			t.Fatalf("%s did not refuse, so its error discloses nothing by accident rather than by design", name)
		}
		t.Run(name, func(t *testing.T) {
			assertNoMaterialInError(t, rerr, materials)
		})
	}

	// And the verifier's side, over the same materials.
	for name, tc := range refusalCases() {
		if tc.needs != nil && !tc.needs(w) {
			continue
		}
		t.Run("Verify, "+name, func(t *testing.T) {
			v, p, req := tc.build(t, w, h)
			_, verr := v.Verify(context.Background(), p, req)
			if verr == nil {
				t.Fatal("Verify() accepted a request it must refuse")
			}
			assertNoMaterialInError(t, verr, materials)
		})
	}
}

// assertNoMaterialInError checks err's text against every encoding of every
// material, using redaction.go's needle set.
func assertNoMaterialInError(t *testing.T, err error, materials map[string][]byte) {
	t.Helper()
	text := err.Error()
	for name, material := range materials {
		for _, n := range leakNeedles(material) {
			if n.contained(text) {
				t.Errorf("the refusal %q discloses %s (%s)", text, name, n.what)
			}
		}
	}
	// A partial disclosure is a disclosure: a message that quoted the first
	// forty characters of a link would pass every whole-value needle above.
	// Forty is long enough that no English phrase matches it by accident and
	// short enough to catch a message that quoted "the link that failed".
	const window = 40
	for name, material := range materials {
		if len(material) < window {
			continue
		}
		for i := 0; i+window <= len(material); i++ {
			if strings.Contains(text, string(material[i:i+window])) {
				t.Errorf("the refusal %q contains a %d-byte run of %s", text, window, name)
				break
			}
		}
	}
}
