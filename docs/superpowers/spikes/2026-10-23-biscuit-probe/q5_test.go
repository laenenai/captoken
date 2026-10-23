package biscuitprobe

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

// Does a bearer-side CHAIN TRUNCATION restore the parent's wider authority?
// This is the exact attack the bespoke envelope.go `Proof` field exists for.
func TestQ5_ChainTruncation(t *testing.T) {
	fmt.Println("\n### Chain truncation")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Authority grants broad access; the attenuation narrows it to read-only.
	auth, err := parser.FromStringBlock(`
		right("doc:1", "read");
		right("doc:1", "write");
		check if resource($r), operation($o), right($r, $o);
	`)
	if err != nil {
		t.Fatal(err)
	}
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(auth); err != nil {
		t.Fatal(err)
	}
	root, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	bb := root.CreateBlock()
	narrow, err := parser.FromStringBlock(`check if operation("read");`)
	if err != nil {
		t.Fatal(err)
	}
	if err := bb.AddBlock(narrow); err != nil {
		t.Fatal(err)
	}
	att, err := root.Append(rand.Reader, bb.Build())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := att.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sealed.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	writeAuthz := `resource("doc:1"); operation("write"); allow if true;`

	// baseline: the honest, sealed, attenuated token must refuse write
	err = authorize(t, raw, pub, writeAuthz)
	fmt.Printf("  %-58s => %s\n", "honest 2-block sealed token, write", verdict(err))

	// the attack: strip the narrowing block at the protobuf layer
	var container pb.Biscuit
	if err := proto.Unmarshal(raw, &container); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("  container: authority + %d block(s), proof kind %T\n",
		len(container.Blocks), container.Proof.Content)
	truncated := &pb.Biscuit{
		Authority: container.Authority,
		Blocks:    nil, // drop the narrowing block
		Proof:     container.Proof,
		RootKeyId: container.RootKeyId,
	}
	traw, err := proto.Marshal(truncated)
	if err != nil {
		t.Fatal(err)
	}
	report(t, "truncated to 1 block, sealed proof kept", traw, pub, writeAuthz)

	// variant: truncate an UNSEALED token, where the bearer also holds the
	// next secret key for the block they are dropping.
	uraw, err := att.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	var uc pb.Biscuit
	if err := proto.Unmarshal(uraw, &uc); err != nil {
		t.Fatal(err)
	}
	utrunc := &pb.Biscuit{Authority: uc.Authority, Blocks: nil, Proof: uc.Proof, RootKeyId: uc.RootKeyId}
	utraw, err := proto.Marshal(utrunc)
	if err != nil {
		t.Fatal(err)
	}
	report(t, "truncated UNSEALED token (bearer holds next secret)", utraw, pub, writeAuthz)

	// variant: truncate, then re-seal using the next secret the bearer holds.
	resealed := &pb.Biscuit{
		Authority: uc.Authority,
		Blocks:    nil,
		Proof:     &pb.Proof{Content: &pb.Proof_NextSecret{NextSecret: uc.Proof.GetNextSecret()}},
		RootKeyId: uc.RootKeyId,
	}
	rraw, err := proto.Marshal(resealed)
	if err != nil {
		t.Fatal(err)
	}
	if rb, uerr := biscuit.Unmarshal(rraw); uerr != nil {
		fmt.Printf("  %-58s => REFUSED at Unmarshal: %v\n", "truncated + re-sealed with held next secret", uerr)
	} else if sb, serr := rb.Seal(rand.Reader); serr != nil {
		fmt.Printf("  %-58s => REFUSED at Seal: %v\n", "truncated + re-sealed with held next secret", serr)
	} else {
		sraw, _ := sb.Serialize()
		report(t, "truncated + re-sealed with held next secret", sraw, pub, writeAuthz)
	}
}

// report authorizes without aborting the test on a refusal.
func report(t *testing.T, label string, raw []byte, pub ed25519.PublicKey, authz string) {
	t.Helper()
	bis, err := biscuit.Unmarshal(raw)
	if err != nil {
		fmt.Printf("  %-58s => REFUSED at Unmarshal: %v\n", label, err)
		return
	}
	a, err := bis.Authorizer(pub)
	if err != nil {
		fmt.Printf("  %-58s => REFUSED at Authorizer: %v\n", label, err)
		return
	}
	parsed, err := parser.FromStringAuthorizer(authz)
	if err != nil {
		t.Fatal(err)
	}
	a.AddAuthorizer(parsed)
	fmt.Printf("  %-58s => %s\n", label, verdict(a.Authorize()))
}

// Does an UNSEALED serialized token hand the recipient the next signing key?
func TestQ5_UnsealedTokenCarriesTheNextSecretKey(t *testing.T) {
	fmt.Println("\n### Key custody in the serialized form")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := parser.FromStringBlock(`right("doc:1","read");`)
	b := biscuit.NewBuilder(priv)
	if err := b.AddBlock(auth); err != nil {
		t.Fatal(err)
	}
	root, _ := b.Build()
	raw, err := root.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	var c pb.Biscuit
	if err := proto.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	switch p := c.Proof.Content.(type) {
	case *pb.Proof_NextSecret:
		fmt.Printf("  UNSEALED token: proof carries NextSecret, %d bytes of PRIVATE key\n", len(p.NextSecret))
	case *pb.Proof_FinalSignature:
		fmt.Printf("  UNSEALED token: proof carries FinalSignature (%d bytes)\n", len(p.FinalSignature))
	}
	// a recipient who only ever saw the bytes can still attenuate
	recv, err := biscuit.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	bb := recv.CreateBlock()
	blk, _ := parser.FromStringBlock(`extra("x");`)
	if err := bb.AddBlock(blk); err != nil {
		t.Fatal(err)
	}
	_, aerr := recv.Append(rand.Reader, bb.Build())
	fmt.Printf("  %-58s => %s\n", "wire-only recipient attenuates an unsealed token",
		map[bool]string{true: "SUCCEEDED (key was in the bytes)", false: "refused"}[aerr == nil])

	sealed, err := root.Seal(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sraw, _ := sealed.Serialize()
	var sc pb.Biscuit
	if err := proto.Unmarshal(sraw, &sc); err != nil {
		t.Fatal(err)
	}
	switch p := sc.Proof.Content.(type) {
	case *pb.Proof_NextSecret:
		fmt.Printf("  SEALED token: proof carries NextSecret, %d bytes (LEAK)\n", len(p.NextSecret))
	case *pb.Proof_FinalSignature:
		fmt.Printf("  SEALED token: proof carries FinalSignature, %d bytes (no key material)\n", len(p.FinalSignature))
	}
}

// Does Authorize() need only the PUBLIC key?
func TestQ5_VerifierNeedsOnlyThePublicKey(t *testing.T) {
	fmt.Println("\n### Verifier key requirement")
	raw, pub := mint(t, `right("doc:1","read"); check if operation("read");`)
	err := authorize(t, raw, pub, `operation("read"); allow if true;`)
	fmt.Printf("  authorize with ed25519.PublicKey only (%d bytes) => %s\n", len(pub), verdict(err))
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := other.Public().(ed25519.PublicKey)
	bis, _ := biscuit.Unmarshal(raw)
	_, aerr := bis.Authorizer(otherPub)
	fmt.Printf("  authorize with a FOREIGN public key => %v\n", aerr)
}

func verdict(err error) string {
	if err != nil {
		return fmt.Sprintf("REFUSED (%v)", err)
	}
	return "AUTHORIZED"
}
