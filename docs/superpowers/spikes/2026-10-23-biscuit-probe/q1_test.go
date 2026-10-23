package biscuitprobe

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

// mintStateful builds a token whose AUTHORITY block carries both an offline
// caveat (expiry-free, pure: resource scope) and a STATEFUL caveat modelled
// as a check over a fact only the authorizing server can supply.
func mintStateful(t *testing.T) (tok []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := parser.FromStringBlock(`
		right("doc:123", "read");
		check if resource($r), operation($op), right($r, $op);
		check if uses_remaining($n), $n > 0;
	`)
	if err != nil {
		t.Fatal(err)
	}
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(authority); err != nil {
		t.Fatal(err)
	}
	bis, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := bis.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw, pub
}

func authorize(t *testing.T, raw []byte, pub ed25519.PublicKey, authz string) error {
	t.Helper()
	bis, err := biscuit.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := bis.Authorizer(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.FromStringAuthorizer(authz)
	if err != nil {
		t.Fatalf("authorizer parse: %v", err)
	}
	a.AddAuthorizer(parsed)
	return a.Authorize()
}

// Q1: does a stateful caveat modelled as a check over a server-only fact
// fail CLOSED for a verifier that does not supply the fact?
func TestQ1_StatefulCheckFailsClosedWhenFactAbsent(t *testing.T) {
	raw, pub := mintStateful(t)

	cases := []struct {
		name  string
		authz string
	}{
		{"A. full verifier, uses remaining", `
			resource("doc:123"); operation("read"); uses_remaining(3);
			allow if true;`},
		{"B. full verifier, uses exhausted", `
			resource("doc:123"); operation("read"); uses_remaining(0);
			allow if true;`},
		{"C. third-party verifier, BLIND to the counter (no uses_remaining fact)", `
			resource("doc:123"); operation("read");
			allow if true;`},
		{"D. third-party verifier, no policy at all", `
			resource("doc:123"); operation("read"); uses_remaining(3);`},
	}
	for _, c := range cases {
		err := authorize(t, raw, pub, c.authz)
		verdict := "AUTHORIZED"
		if err != nil {
			verdict = "REFUSED"
		}
		fmt.Printf("\n--- %s\n    => %s\n", c.name, verdict)
		if err != nil {
			fmt.Printf("    err: %v\n", err)
		}
	}
}

// Q1b: can the BEARER forge the server-only fact by appending an
// attenuation block that asserts uses_remaining(999)?
func TestQ1b_BearerCannotForgeServerFactViaAttenuation(t *testing.T) {
	raw, pub := mintStateful(t)
	bis, err := biscuit.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	bb := bis.CreateBlock()
	blk, err := parser.FromStringBlock(`uses_remaining(999);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := bb.AddBlock(blk); err != nil {
		t.Fatal(err)
	}
	attenuated, err := bis.Append(rand.Reader, bb.Build())
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := attenuated.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	err = authorize(t, raw2, pub, `
		resource("doc:123"); operation("read");
		allow if true;`)
	verdict := "AUTHORIZED (FAIL-OPEN: bearer forged the counter)"
	if err != nil {
		verdict = "REFUSED (bearer-asserted fact did not satisfy the authority check)"
	}
	fmt.Printf("\n--- E. bearer appends block asserting uses_remaining(999)\n    => %s\n", verdict)
	if err != nil {
		fmt.Printf("    err: %v\n", err)
	}
}

// Q1c: a check in an ATTENUATION block over a server-only fact — the shape
// captoken would use if a delegator narrowed a token with MaxUses.
func TestQ1c_StatefulCheckInAttenuationBlock(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := parser.FromStringBlock(`right("doc:123", "read");`)
	if err != nil {
		t.Fatal(err)
	}
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(authority); err != nil {
		t.Fatal(err)
	}
	bis, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	bb := bis.CreateBlock()
	blk, err := parser.FromStringBlock(`check if uses_remaining($n), $n > 0;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := bb.AddBlock(blk); err != nil {
		t.Fatal(err)
	}
	att, err := bis.Append(rand.Reader, bb.Build())
	if err != nil {
		t.Fatal(err)
	}
	// now a SECOND attenuation by the bearer, forging the fact
	bb2 := att.CreateBlock()
	blk2, err := parser.FromStringBlock(`uses_remaining(999);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := bb2.AddBlock(blk2); err != nil {
		t.Fatal(err)
	}
	att2, err := att.Append(rand.Reader, bb2.Build())
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		b    *biscuit.Biscuit
	}{
		{"F. block-1 stateful check, verifier blind (no fact)", att},
		{"G. block-1 stateful check, LATER block-2 forges uses_remaining(999)", att2},
	} {
		raw, err := c.b.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		err = authorize(t, raw, pub, `
			resource("doc:123"); operation("read");
			allow if right("doc:123", "read");`)
		verdict := "AUTHORIZED"
		if err != nil {
			verdict = "REFUSED"
		}
		fmt.Printf("\n--- %s\n    => %s\n", c.name, verdict)
		if err != nil {
			fmt.Printf("    err: %v\n", err)
		}
	}
}
