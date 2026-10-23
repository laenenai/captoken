package biscuitprobe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

// Does Datalog arithmetic overflow the way the bespoke MaxBytesTransferred
// check was rewritten to avoid?
func TestQ2_Int64OverflowInDatalogArithmetic(t *testing.T) {
	fmt.Println("\n### int64 overflow in `$before + $len <= limit`")
	// bespoke guards this by rearranging to  $len <= limit - $before
	chk := `check if bytes_before($b), content_length($c), $b + $c <= 1000;`
	run(t, "honest: 100 + 200 <= 1000", chk, `bytes_before(100); content_length(200); allow if true;`)
	run(t, "honest over: 900 + 200 <= 1000", chk, `bytes_before(900); content_length(200); allow if true;`)
	run(t, "OVERFLOW: 9223372036854775807 + 1", chk,
		`bytes_before(9223372036854775807); content_length(1); allow if true;`)
	fmt.Println("  -- the rearranged, overflow-free form the bespoke code uses:")
	chk2 := `check if bytes_before($b), content_length($c), $b >= 0, $c >= 0, $c <= 1000 - $b;`
	run(t, "rearranged, OVERFLOW input", chk2,
		`bytes_before(9223372036854775807); content_length(1); allow if true;`)
	run(t, "rearranged, honest", chk2, `bytes_before(100); content_length(200); allow if true;`)
}

// Q4: revocation identifiers.
func TestQ4_RevocationIdentifiers(t *testing.T) {
	fmt.Println("\n### Revocation identifiers")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parser.FromStringBlock(`right("doc:1","read");`)
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(auth); err != nil {
		t.Fatal(err)
	}
	root, _ := b.Build()
	show := func(label string, bi *biscuit.Biscuit) {
		ids := bi.RevocationIds()
		fmt.Printf("  %-40s blocks=%d ids=%d\n", label, bi.BlockCount(), len(ids))
		for i, id := range ids {
			fmt.Printf("      [%d] %s (%d bytes)\n", i, hex.EncodeToString(id), len(id))
		}
	}
	show("root (1 block)", root)

	bb := root.CreateBlock()
	blk, _ := parser.FromStringBlock(`check if operation("read");`)
	if err := bb.AddBlock(blk); err != nil {
		t.Fatal(err)
	}
	att, err := root.Append(rand.Reader, bb.Build())
	if err != nil {
		t.Fatal(err)
	}
	show("attenuated (2 blocks)", att)

	sealed, err := att.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	show("sealed", sealed)

	// Are they stable across serialize/deserialize?
	raw, _ := att.Serialize()
	rt, err := biscuit.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	show("attenuated, after round trip", rt)

	// Do two independent Appends of the SAME block content get the same id?
	bb2 := root.CreateBlock()
	blk2, _ := parser.FromStringBlock(`check if operation("read");`)
	if err := bb2.AddBlock(blk2); err != nil {
		t.Fatal(err)
	}
	att2, err := root.Append(rand.Reader, bb2.Build())
	if err != nil {
		t.Fatal(err)
	}
	show("second Append, identical content", att2)

	_ = pub
}

// Can revocation be enforced INSIDE the token's own Datalog, or must it be
// an out-of-band lookup?
func TestQ4_RevocationAsADatalogCheck(t *testing.T) {
	fmt.Println("\n### Revocation expressed as a check")
	run(t, "token demands a not_revoked fact", `check if not_revoked();`,
		`not_revoked(); allow if true;`)
	run(t, "verifier omits not_revoked (blind)", `check if not_revoked();`,
		`allow if true;`)
	fmt.Println("  -- but the token cannot name its OWN revocation id in a check:")
	fmt.Println("     the id is derived from the signature, which does not exist")
	fmt.Println("     until after the block carrying the check is signed.")
}
