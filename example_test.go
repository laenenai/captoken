package captoken_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/laenenai/captoken"
)

func Example() {
	schema, err := captoken.NewResourceSchema(
		captoken.SegmentKind{Name: "tenant"},
		captoken.SegmentKind{Name: "fileset", Repeats: true},
		captoken.SegmentKind{Name: "document"},
	)
	if err != nil {
		panic(err)
	}
	tenant, err := schema.Path(captoken.Segment{Kind: "tenant", ID: "acme"})
	if err != nil {
		panic(err)
	}
	document, err := schema.Path(
		captoken.Segment{Kind: "tenant", ID: "acme"},
		captoken.Segment{Kind: "fileset", ID: "contracts"},
		captoken.Segment{Kind: "document", ID: "d-1"},
	)
	if err != nil {
		panic(err)
	}

	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	clock := captoken.NewFixedClock(now)
	rootKey, err := captoken.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	minter, err := captoken.NewMinter(captoken.MinterConfig{
		Issuer:  "issuer.example",
		RootKey: rootKey.Private,
		Schema:  schema,
		Clock:   clock,
	})
	if err != nil {
		panic(err)
	}

	root, err := minter.Mint(captoken.MintSpec{
		Type:        captoken.TypeDelegation,
		Subject:     "alice",
		Audience:    []captoken.Audience{"api.example"},
		ExpiresAt:   now.Add(24 * time.Hour),
		Permissions: captoken.NewPermissionSet("doc.read", "doc.write"),
		Resources:   []captoken.ResourcePath{tenant},
	})
	if err != nil {
		panic(err)
	}

	deriver, err := captoken.NewDeriver(captoken.DeriverConfig{Schema: schema, Clock: clock})
	if err != nil {
		panic(err)
	}
	leaf, err := deriver.Derive(root.Token, root.HolderKey, captoken.MintSpec{
		Type:        captoken.TypeExecution,
		Subject:     "alice",
		Audience:    []captoken.Audience{"api.example"},
		ExpiresAt:   now.Add(time.Hour),
		Permissions: captoken.NewPermissionSet("doc.read"),
		Resources:   []captoken.ResourcePath{document},
	})
	if err != nil {
		panic(err)
	}

	memory := captoken.NewMemory()
	verifier, err := captoken.NewVerifier(captoken.VerifierConfig{
		Issuer:      "issuer.example",
		RootKeys:    []ed25519.PublicKey{rootKey.Public},
		Audience:    "api.example",
		Schema:      schema,
		Clock:       clock,
		Revocations: memory,
	})
	if err != nil {
		panic(err)
	}
	verified, err := verifier.Verify(context.Background(), leaf.Token, captoken.Request{
		Permission: "doc.read",
		Resource:   document,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(verified.Subject, verified.Permissions.Contains("doc.read"), len(verified.TerminalResources))
	// Output: alice true 1
}
