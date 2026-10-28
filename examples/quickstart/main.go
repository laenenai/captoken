// Command quickstart mints a delegation token, narrows it to an execution
// token, and verifies the result.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/laenenai/captoken"
)

func main() {
	schema, err := captoken.NewResourceSchema(
		captoken.SegmentKind{Name: "tenant"},
		captoken.SegmentKind{Name: "document"},
	)
	must(err)
	tenant, err := schema.Path(captoken.Segment{Kind: "tenant", ID: "acme"})
	must(err)
	document, err := schema.Path(
		captoken.Segment{Kind: "tenant", ID: "acme"},
		captoken.Segment{Kind: "document", ID: "d-1"},
	)
	must(err)

	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	clock := captoken.NewFixedClock(now)
	rootKey, err := captoken.GenerateKey(nil)
	must(err)
	minter, err := captoken.NewMinter(captoken.MinterConfig{
		Issuer: "issuer.example", RootKey: rootKey.Private, Schema: schema, Clock: clock,
	})
	must(err)

	root, err := minter.Mint(captoken.MintSpec{
		Type:        captoken.TypeDelegation,
		Subject:     "alice",
		Audience:    []captoken.Audience{"api.example"},
		ExpiresAt:   now.Add(24 * time.Hour),
		Permissions: captoken.NewPermissionSet("doc.read", "doc.write"),
		Resources:   []captoken.ResourcePath{tenant},
	})
	must(err)

	deriver, err := captoken.NewDeriver(captoken.DeriverConfig{Schema: schema, Clock: clock})
	must(err)
	leaf, err := deriver.Derive(root.Token, root.HolderKey, captoken.MintSpec{
		Type:        captoken.TypeExecution,
		Subject:     "alice",
		Audience:    []captoken.Audience{"api.example"},
		ExpiresAt:   now.Add(time.Hour),
		Permissions: captoken.NewPermissionSet("doc.read"),
		Resources:   []captoken.ResourcePath{document},
	})
	must(err)

	memory := captoken.NewMemory()
	verifier, err := captoken.NewVerifier(captoken.VerifierConfig{
		Issuer:      "issuer.example",
		RootKeys:    []ed25519.PublicKey{rootKey.Public},
		Audience:    "api.example",
		Schema:      schema,
		Clock:       clock,
		Revocations: memory,
	})
	must(err)
	verified, err := verifier.Verify(context.Background(), leaf.Token, captoken.Request{
		Permission: "doc.read",
		Resource:   document,
	})
	must(err)
	_, _ = fmt.Fprintf(os.Stdout, "subject=%s permission=doc.read resources=%d\n", verified.Subject, len(verified.TerminalResources))
}

func must(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
