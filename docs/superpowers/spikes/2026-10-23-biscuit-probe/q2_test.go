package biscuitprobe

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

func mint(t *testing.T, authorityCode string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := parser.FromStringBlock(authorityCode)
	if err != nil {
		t.Fatalf("authority parse %q: %v", authorityCode, err)
	}
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(blk); err != nil {
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

func run(t *testing.T, label, authority, authz string) {
	t.Helper()
	raw, pub := mint(t, authority)
	err := authorize(t, raw, pub, authz)
	v := "AUTHORIZED"
	if err != nil {
		v = "REFUSED"
	}
	fmt.Printf("  %-62s => %s\n", label, v)
	if err != nil {
		fmt.Printf("      %v\n", err)
	}
}

// Is the check language even able to express each caveat?
func TestQ2_CaveatExpressibility(t *testing.T) {
	fmt.Println("\n### ResourceScope over a hierarchical ref (prefix matching)")
	scope := `check if resource($r), $r.starts_with("tenant/t1/fs/a/doc/");`
	run(t, "in-scope doc", scope, `resource("tenant/t1/fs/a/doc/123"); allow if true;`)
	run(t, "sibling fileset", scope, `resource("tenant/t1/fs/b/doc/123"); allow if true;`)
	fmt.Println("  -- prefix-boundary hazard: a scope that does NOT end at a separator")
	bad := `check if resource($r), $r.starts_with("tenant/t1/fs/a");`
	run(t, "scope 'fs/a' leaks into 'fs/ab' (sibling!)", bad, `resource("tenant/t1/fs/ab/doc/9"); allow if true;`)

	fmt.Println("\n### AllowedContentTypes (exact match against the sniffed type)")
	ct := `check if content_type($t), ["application/pdf", "image/png"].contains($t);`
	run(t, "sniffed application/pdf", ct, `content_type("application/pdf"); allow if true;`)
	run(t, "parameter-smuggled type", ct, `content_type("application/pdf; charset=../../x"); allow if true;`)
	run(t, "content_type fact ABSENT (verifier did not sniff)", ct, `allow if true;`)

	fmt.Println("\n### MaxContentLength")
	cl := `check if content_length($n), $n <= 1048576;`
	run(t, "1 MiB exactly", cl, `content_length(1048576); allow if true;`)
	run(t, "1 MiB + 1", cl, `content_length(1048577); allow if true;`)
	run(t, "unknown length (fact absent, chunked request)", cl, `allow if true;`)
	// NOTE: `content_length(-1)` does not PARSE -- see TestQ2_ParserLimits.

	fmt.Println("\n### ProcessorAudience (certificate thumbprint, exact)")
	pa := `check if processor($p), $p == "sha256:aabbcc";`
	run(t, "matching thumbprint", pa, `processor("sha256:aabbcc"); allow if true;`)
	run(t, "other processor", pa, `processor("sha256:ddeeff"); allow if true;`)
	run(t, "no processor identity presented", pa, `allow if true;`)

	fmt.Println("\n### RequireDeclaredDigest / RequireAuthenticatedRecipient (presence)")
	rd := `check if declared_digest($d);`
	run(t, "digest declared", rd, `declared_digest("blake3:1234"); allow if true;`)
	run(t, "no digest declared", rd, `allow if true;`)

	fmt.Println("\n### Watermark (slot path equality)")
	wm := `check if slot_path($s), $s == "renditions/watermarked";`
	run(t, "watermarked rendition", wm, `slot_path("renditions/watermarked"); allow if true;`)
	run(t, "the original", wm, `slot_path("original"); allow if true;`)

	fmt.Println("\n### RequiredReadiness (set membership)")
	rr := `check if readiness($s), ["ready", "indexed"].contains($s);`
	run(t, "ready", rr, `readiness("ready"); allow if true;`)
	run(t, "ingesting", rr, `readiness("ingesting"); allow if true;`)

	fmt.Println("\n### ExpiresAt / NotBefore (Date terms)")
	ex := `check if time($t), $t <= 2026-10-23T12:00:00Z;`
	run(t, "before expiry", ex, `time(2026-10-23T11:00:00Z); allow if true;`)
	run(t, "after expiry", ex, `time(2026-10-23T13:00:00Z); allow if true;`)
	run(t, "no time fact supplied at all", ex, `allow if true;`)

	fmt.Println("\n### DelegationDepth -- is block count visible to Datalog?")
	run(t, "server-supplied chain_depth fact", `check if chain_depth($d), $d <= 2;`,
		`chain_depth(2); allow if true;`)
	run(t, "chain_depth fact absent", `check if chain_depth($d), $d <= 2;`,
		`allow if true;`)
}

// ClientCIDR: is there any native IP/CIDR term or operator?
func TestQ2_ClientCIDR_NoNativeSupport(t *testing.T) {
	fmt.Println("\n### ClientCIDR")
	for _, code := range []string{
		`check if client_ip($ip), $ip.in_cidr("10.0.0.0/8");`,
		`check if client_ip($ip), $ip in 10.0.0.0/8;`,
		`check if client_ip($ip), cidr("10.0.0.0/8").contains($ip);`,
	} {
		_, err := parser.FromStringBlock(code)
		fmt.Printf("  parse %-55q\n", code)
		if err != nil {
			fmt.Printf("      PARSE ERROR: %v\n", err)
		} else {
			fmt.Printf("      parsed OK\n")
		}
	}
	fmt.Println("  -- string prefix as a substitute is semantically wrong for non-octet prefixes:")
	// 10.16.0.0/12 covers 10.16.0.0 - 10.31.255.255. No string prefix expresses that.
	run(t, "10.16.0.0/12 approximated as starts_with(\"10.1\")", `check if client_ip($ip), $ip.starts_with("10.1");`,
		`client_ip("10.100.0.5"); allow if true;`)
	fmt.Println("      (10.100.0.5 is OUTSIDE 10.16.0.0/12 but matches the prefix \"10.1\")")
	fmt.Println("  -- regex operator exists; test whether it is available and what engine:")
	run(t, "regex on client_ip", `check if client_ip($ip), $ip.matches("^10\\.(1[6-9]|2[0-9]|3[01])\\.");`,
		`client_ip("10.100.0.5"); allow if true;`)
	run(t, "regex on in-range address", `check if client_ip($ip), $ip.matches("^10\\.(1[6-9]|2[0-9]|3[01])\\.");`,
		`client_ip("10.20.0.5"); allow if true;`)
	fmt.Println("  -- the server-supplied-fact form, which is the fail-closed shape:")
	run(t, "server resolves CIDR and asserts client_in_cidr", `check if client_in_cidr("10.16.0.0/12");`,
		`client_in_cidr("10.16.0.0/12"); allow if true;`)
	run(t, "verifier cannot resolve CIDR -> fact absent", `check if client_in_cidr("10.16.0.0/12");`,
		`allow if true;`)
}

// Attenuation monotonicity: can an appended block WIDEN anything?
func TestQ2_AttenuationCannotWiden(t *testing.T) {
	fmt.Println("\n### Attenuation monotonicity (the Narrows() equivalent)")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parser.FromStringBlock(`
		right("doc:123", "read");
		check if resource($r), operation($op), right($r, $op);
	`)
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(auth); err != nil {
		t.Fatal(err)
	}
	bis, _ := b.Build()

	// bearer appends a block granting itself a wider right
	bb := bis.CreateBlock()
	wider, _ := parser.FromStringBlock(`right("doc:999", "write");`)
	if err := bb.AddBlock(wider); err != nil {
		t.Fatal(err)
	}
	att, err := bis.Append(rand.Reader, bb.Build())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := att.Serialize()

	err = authorize(t, raw, pub, `
		resource("doc:999"); operation("write");
		allow if right("doc:999", "write");`)
	v := "AUTHORIZED (WIDENED! fail-open)"
	if err != nil {
		v = "REFUSED (block fact did not reach the authority check or policy)"
	}
	fmt.Printf("  %-62s => %s\n", "bearer appends right(\"doc:999\",\"write\")", v)
	if err != nil {
		fmt.Printf("      %v\n", err)
	}

	// and can a sealed token still be appended to?
	sealed, err := att.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sraw, _ := sealed.Serialize()
	sb, err := biscuit.Unmarshal(sraw)
	if err != nil {
		t.Fatal(err)
	}
	bb2 := sb.CreateBlock()
	more, _ := parser.FromStringBlock(`right("doc:1","read");`)
	if err := bb2.AddBlock(more); err != nil {
		t.Fatal(err)
	}
	_, aerr := sb.Append(rand.Reader, bb2.Build())
	v = "APPENDED (seal did not hold)"
	if aerr != nil {
		v = "REFUSED"
	}
	fmt.Printf("  %-62s => %s\n", "append to a SEALED token", v)
	if aerr != nil {
		fmt.Printf("      %v\n", aerr)
	}
}
