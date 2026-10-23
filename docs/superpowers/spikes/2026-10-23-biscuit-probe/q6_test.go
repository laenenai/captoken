package biscuitprobe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

// Are revocation ids a CANONICAL identity for a token, i.e. safe to key a
// single-use counter on? The bespoke code keys on Fingerprint(t) precisely
// because the presented bytes are not unique for a semantic token.
func TestQ6_RevocationIdsAreCanonicalUnderBytePermutation(t *testing.T) {
	fmt.Println("\n### Is a revocation id a safe single-use key?")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parser.FromStringBlock(`right("doc:1","read"); check if operation("read");`)
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(auth); err != nil {
		t.Fatal(err)
	}
	root, _ := b.Build()
	sealed, err := root.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sealed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ids := func(bs []byte) string {
		bi, err := biscuit.Unmarshal(bs)
		if err != nil {
			return "UNPARSEABLE: " + err.Error()
		}
		if _, err := bi.Authorizer(pub); err != nil {
			return "SIG REFUSED: " + err.Error()
		}
		out := ""
		for _, id := range bi.RevocationIds() {
			out += hex.EncodeToString(id)[:16] + " "
		}
		return out
	}
	fmt.Printf("  original          (%4d bytes) ids: %s\n", len(raw), ids(raw))

	// permutation 1: append an UNKNOWN protobuf field to the container
	perm := append([]byte(nil), raw...)
	// field 15, wire type 2 (length-delimited), 3 bytes of payload
	perm = append(perm, 0x7a, 0x03, 0xde, 0xad, 0xbe)
	fmt.Printf("  + unknown pb field(%4d bytes) ids: %s\n", len(perm), ids(perm))
	fmt.Printf("    bytes differ from original: %v\n", !bytes.Equal(raw, perm))

	// permutation 2: re-marshal the container (protobuf field order is not
	// guaranteed stable across encoders / languages)
	var c pb.Biscuit
	if err := proto.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	re, err := proto.MarshalOptions{Deterministic: false}.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("  re-marshalled     (%4d bytes) ids: %s\n", len(re), ids(re))
	fmt.Printf("    bytes differ from original: %v\n", !bytes.Equal(raw, re))
}
