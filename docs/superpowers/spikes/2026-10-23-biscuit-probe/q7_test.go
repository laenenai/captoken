package biscuitprobe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

// Token size: signed links go in URLs, so this is a real constraint.
func TestQ7_TokenSize(t *testing.T) {
	fmt.Println("\n### Token size for a realistic captoken caveat set")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// the caveat set a CAS signed download link would actually carry
	code := `
		subject("prn:7f3a9c21-4e8b-11ef-9c4d-0242ac120002");
		right("tenant/t1/fs/marketing/doc/d42", "read");
		check if resource($r), operation($o), right($r, $o);
		check if time($t), $t <= 2026-10-24T09:00:00Z;
		check if content_type($c), ["application/pdf"].contains($c);
		check if content_length($n), $n <= 10485760;
		check if slot_path($s), $s == "renditions/watermarked";
		check if readiness($s2), ["ready"].contains($s2);
		check if processor($p), $p == "sha256:9f8e7d6c5b4a39281716";
		check if declared_digest($d);
		check if client_in_cidr("10.16.0.0/12");
		check if uses_remaining($u), $u > 0;
		check if bytes_remaining($b), content_length($cl), $cl <= $b;
		check if chain_depth($cd), $cd <= 3;
		check if not_revoked();
	`
	blk, err := parser.FromStringBlock(code)
	if err != nil {
		t.Fatal(err)
	}
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(blk); err != nil {
		t.Fatal(err)
	}
	root, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := root.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sealed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	fmt.Printf("  15 checks, 1 block, sealed: %d raw bytes, %d base64url chars\n", len(raw), len(enc))

	// plus one attenuation
	bb := root.CreateBlock()
	nb, _ := parser.FromStringBlock(`check if operation("read"); check if time($t), $t <= 2026-10-23T18:00:00Z;`)
	if err := bb.AddBlock(nb); err != nil {
		t.Fatal(err)
	}
	att, err := root.Append(rand.Reader, bb.Build())
	if err != nil {
		t.Fatal(err)
	}
	as, err := att.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	araw, _ := as.Serialize()
	fmt.Printf("  + 1 attenuation block:      %d raw bytes, %d base64url chars\n",
		len(araw), len(base64.RawURLEncoding.EncodeToString(araw)))
	fmt.Printf("  (URL length budget is commonly ~2000 chars)\n")
}
