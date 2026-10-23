package chain

// This file is what keeps subsumption_test.go honest.
//
// An adversarial suite in which every attack is refused proves nothing on
// its own: a Verify that refused everything would pass it, and so would one
// where several attacks happen to be caught by a single incidental check
// while the guard the suite names does nothing. So every guard is removed in
// turn — through Verifier.weak, whose zero value is fully strict so that
// production cannot weaken anything by forgetting to set it — and two things
// are asserted:
//
//   - removing a guard must make at least one attack in the suite SUCCEED.
//     A guard no attack exercises is an untested guard, and a guard whose
//     removal changes nothing is either dead code or redundant with another
//     check that is doing the work.
//   - removing a guard must leave the honest chain still verifying. A
//     "mutation" that broke verification outright would make every attack
//     fail for the wrong reason, and the first assertion would be satisfied
//     by an accident.
//
// # One honest finding this test produced
//
// par_hash is NOT an independent bound on authority, and the first version
// of this test wrongly claimed it was. Because every link must RESTATE every
// caveat kind its parent carries, at a value at least as restrictive, and
// because verification computes the chain's authority as the intersection of
// every link, the terminal link always dominates: swapping an ancestor for a
// wider sibling cannot add authority, because the leaf is already narrower
// than both. What par_hash does secure is the chain's PROVENANCE — that a
// link descends from the parent it says it does — which matters as the
// backstop for the restatement rule and as the audit record of who delegated
// what to whom. The witness below is written to show exactly that and
// nothing more.

import (
	"context"
	"errors"
	"testing"
)

// guardWitness maps each verification guard to an attack that stops being
// refused when that guard alone is removed. Every field of weakened must
// appear here, and TestEveryGuardHasAWitness checks that it does.
func guardWitness() map[string]func(t *testing.T, f fixture) string {
	return map[string]func(t *testing.T, f fixture) string{
		"permissions": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) { addPermission(c, "doc.delete") })
		},
		"resources": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) {
				c.Resources = [][][]string{{{"tenant", "t1"}}}
			})
		},
		"window": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) {
				c.ExpiresAt = f.claims[0].ExpiresAt + 86400
			})
		},
		"caveats": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) { setCaveat(t, c, "max_content_length", 1<<30) })
		},
		"parent_hash": func(t *testing.T, f fixture) string {
			// The honest leaf, UNTOUCHED, presented under a wider sibling
			// that reused the same child key. Its signature verifies —
			// the sibling bound the same key — its claims narrow the
			// sibling, and its chain id matches. Only par_hash, which the
			// leaf itself committed to and which the adversary cannot
			// re-sign without the leaf's key, says this is not the chain
			// the leaf was issued into.
			return present([]string{f.tokens[0], f.wideSibling(t), f.tokens[2]})
		},
		"type_order": func(_ *testing.T, f fixture) string {
			return present(f.tokens[:2])
		},
		"chain_id": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) { c.ChainID = "not-the-ancestors-id" })
		},
		"issuer": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) { c.Issuer = "issuer-2" })
		},
		"audience": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) {
				c.Audience = []string{testAudience, "some-other-verifier"}
			})
		},
		"stateful_placement": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) { setCaveat(t, c, "max_uses", 1) })
		},
		"version": func(t *testing.T, f fixture) string {
			return f.rebuild(t, 2, func(c *claims) { c.Version = FormatVersion + 1 })
		},
		"signature": func(t *testing.T, f fixture) string {
			forged, err := GenerateKey(nil)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			c := f.claims[2]
			c.ParentHash = parentHash(signingInput(f.tokens[0]))
			tok, err := signLink(c, forged.Private)
			if err != nil {
				t.Fatalf("signLink() error = %v", err)
			}
			return present([]string{f.tokens[0], tok})
		},
	}
}

// mutations is one weakened value per guard, keyed by the guard's name.
func mutations() map[string]weakened {
	return map[string]weakened{
		"permissions":        {permissions: true},
		"resources":          {resources: true},
		"window":             {window: true},
		"caveats":            {caveats: true},
		"parent_hash":        {parentHash: true},
		"type_order":         {typeOrder: true},
		"chain_id":           {chainID: true},
		"issuer":             {issuer: true},
		"audience":           {audience: true},
		"stateful_placement": {statefulPlacement: true},
		"version":            {version: true},
		"signature":          {signature: true},
	}
}

// TestEveryGuardHasAWitness fails if a guard is added to weakened without
// an attack that exercises it, which is the way an untested guard would
// otherwise arrive.
func TestEveryGuardHasAWitness(t *testing.T) {
	t.Parallel()

	const guardCount = 12 // one per field of weakened
	if got := len(mutations()); got != guardCount {
		t.Fatalf("mutations() covers %d guards, want %d: a field was added to weakened without a mutation", got, guardCount)
	}
	for guard := range mutations() {
		if _, ok := guardWitness()[guard]; !ok {
			t.Errorf("guard %q has no witness attack", guard)
		}
	}
}

// TestGuards_EveryOneIsLoadBearing removes each guard on its own and
// asserts its witness attack stops being refused. That is what makes the
// adversarial suite's green a statement about the guards rather than about
// Verify refusing things in general.
func TestGuards_EveryOneIsLoadBearing(t *testing.T) {
	t.Parallel()

	witnesses := guardWitness()
	for guard, weak := range mutations() {
		t.Run(guard, func(t *testing.T) {
			t.Parallel()
			f := honestChain(t)
			presented := witnesses[guard](t, f)

			// Strict: the witness must be refused.
			if _, err := f.verifier(t, weakened{}, nil).Verify(
				context.Background(), presented, f.request(t),
			); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("with every guard in place, the %s witness is NOT refused (error = %v): "+
					"it is not an attack, so it proves nothing about the %s guard", guard, err, guard)
			}

			// Weakened: it must now get through.
			if _, err := f.verifier(t, weak, nil).Verify(
				context.Background(), presented, f.request(t),
			); errors.Is(err, ErrInvalidToken) {
				t.Fatalf("with the %s guard removed, its witness is still refused (error = %v): "+
					"either the guard is not what refuses it, or another check is silently doing "+
					"the same job and the %s guard is untested", guard, err, guard)
			}
		})
	}
}

// TestGuards_HonestChainSurvivesEveryMutation is the other half. A mutation
// that broke verification outright would satisfy the test above by
// accident — every attack would fail, for the wrong reason — so each
// weakening must still accept the honest chain.
func TestGuards_HonestChainSurvivesEveryMutation(t *testing.T) {
	t.Parallel()

	for guard, weak := range mutations() {
		t.Run(guard, func(t *testing.T) {
			t.Parallel()
			f := honestChain(t)
			if _, err := f.verifier(t, weak, nil).Verify(
				context.Background(), present(f.tokens), f.request(t),
			); err != nil {
				t.Fatalf("with the %s guard removed, the honest chain no longer verifies: %v\n"+
					"a mutation must weaken verification, not break it", guard, err)
			}
		})
	}
}
