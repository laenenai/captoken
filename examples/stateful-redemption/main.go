// Command stateful-redemption shows a single-use redemption token: the
// reservation service reads the counter, verifies, performs the operation,
// and advances the counter only on success.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
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

	// The reservation service owns both the counters and the revocation
	// records. Memory is only an in-process test adapter.
	counters := captoken.NewMemory()
	revocations := captoken.NewMemory()

	minter, err := captoken.NewMinter(captoken.MinterConfig{
		Issuer: "issuer.example", RootKey: rootKey.Private, Schema: schema, Clock: clock,
	})
	must(err)
	root, err := minter.Mint(captoken.MintSpec{
		Type:        captoken.TypeDelegation,
		Subject:     "alice",
		Audience:    []captoken.Audience{"reservations.example"},
		ExpiresAt:   now.Add(24 * time.Hour),
		Permissions: captoken.NewPermissionSet("doc.read"),
		Resources:   []captoken.ResourcePath{tenant},
	})
	must(err)

	deriver, err := captoken.NewDeriver(captoken.DeriverConfig{Schema: schema, Clock: clock})
	must(err)
	redemption, err := deriver.Derive(root.Token, root.HolderKey, captoken.MintSpec{
		Type:        captoken.TypeRedemption,
		Subject:     "alice",
		Audience:    []captoken.Audience{"reservations.example"},
		ExpiresAt:   now.Add(time.Hour),
		Permissions: captoken.NewPermissionSet("doc.read"),
		Resources:   []captoken.ResourcePath{document},
		Caveats:     []captoken.Caveat{captoken.MaxUses(1)},
	})
	must(err)

	verifier, err := captoken.NewVerifier(captoken.VerifierConfig{
		Issuer:       "issuer.example",
		RootKeys:     []ed25519.PublicKey{rootKey.Public},
		Audience:     "reservations.example",
		Schema:       schema,
		Clock:        clock,
		Reservations: counters,
		Revocations:  revocations,
	})
	must(err)

	ctx := context.Background()
	request := captoken.Request{Permission: "doc.read", Resource: document}
	verified, err := verifier.Verify(ctx, redemption.Token, request)
	must(err)

	// The guarded operation happens here. The counter is advanced only after
	// it succeeds, and in the same transaction in a real deployment.
	if err := counters.Advance(ctx, verified.ChainID, captoken.Advance{Uses: 1}); err != nil {
		must(err)
	}

	_, err = verifier.Verify(ctx, redemption.Token, request)
	if !errors.Is(err, captoken.ErrCaveatNotSatisfied) {
		must(fmt.Errorf("second redemption: %w", err))
	}
	_, _ = fmt.Fprintln(os.Stdout, "first-redemption=allowed second-redemption=refused")
}

func must(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
