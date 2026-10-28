package captokentest

// This file holds the part of the contract that is about the PRESENTATION —
// the chain as a string — rather than about any one link's content, and the
// measurement that makes it reachable from outside this module.
//
// Why it exists at all: before it, the exported suite presented exactly two
// strings to a verifier, an honest chain and that chain with "tampered"
// appended. chain's adversarial suite attacks a presentation
// twenty-three different ways, but it forges links directly — it is an
// internal test precisely so it can — and nothing a consumer could call
// reached any of it. So a consumer could not detect an implementation that
// accepted a REORDERED chain, which is the plainest forgery there is: the
// same links, in an order nobody signed. CAS measured that when it adopted
// captoken v0.1.1 and found thirteen wire-format and codec properties
// running only in captoken's own CI.
//
// Every attack below is built with nothing but the exported surface:
// captoken.Prefix, captoken.Separator and the presentation the
// implementation itself produced. None of them assembles a link, because
// assembling a link means knowing the claim set's member order and
// re-signing it — see "What stays internal, and why" below.
//
// # Why the geometry is measured and not assumed
//
// Positioning a link boundary needs to know where the links start. The
// presentation syntax is published and its two constants are exported, so
// splitting on them is going through the port rather than behind it — but a
// split is still an assumption until something checks it, so
// measurePresentation checks the split it computed against the
// implementation's OWN report of the chain's shape: Verified.Depth, which
// Verify fills in from the chain it just walked. A presentation that splits
// into a different number of links than the verifier counted fails the
// measurement by name, with both numbers, rather than failing a tamper
// assertion for a reason nobody can read.
//
// Within a link the same rule applies one level down. A link is a compact
// JWS with exactly three dot-separated segments — docs/wire-format.md
// publishes that, and a presentation carrying anything else is refused
// before a signature is checked — so the segment boundaries are measured
// from the link's own dots. Nothing here assumes anything about what a
// segment contains.
//
// # Why the sweeps here are sampled
//
// A three-link presentation is around 2,400 bytes, and all but a hundred or
// so of them are base64url payload where an alteration is caught by the
// signature over that payload — the same check, at every one of two
// thousand positions. Sweeping all of them buys repetition rather than
// coverage, and it buys it in every consumer's CI, under -race, once per
// subtest.
//
// So these sweeps sample at the positions where a presentation-level bug
// actually lives: every byte of the prefix, every separator, and per link
// every dot and the first and last byte of each of its three segments, plus
// a few interior offsets. The interior samples are what -short drops; the
// structural ones always run, because they are the sweep's whole value and
// they are cheap.
//
// **Do not "fix" these into exhaustive sweeps.** The named properties above
// them — a reordered chain, a dropped link, a duplicated link, a spliced
// link — are not reached by sampling harder, and an exhaustive version of
// either loop would be a slow test that a consumer eventually switches off,
// which protects nothing. presentation_test.go fails if the sample grows
// past a bound no sampled sweep needs.
//
// # Why the alteration is the ASCII case bit
//
// The sweep flips 0x20 — the bit that distinguishes 'a' from 'A' — rather
// than 0x01, and the choice is load-bearing rather than cosmetic.
//
// Every byte of a presentation is base64url, a dot, a separator, or part of
// the prefix. XOR 0x20 maps a base64url LETTER to the letter of the other
// case, whose six-bit value differs by 26 and therefore in its top two bits
// always (a value in 0..25 and its partner in 26..51 cannot share a
// quotient by 16), so the decoded bytes differ and the signature over them
// fails. Applied to any other character — a digit, '-', '_', '.', '~' or a
// prefix byte — it produces something outside the alphabet or outside the
// syntax, and the presentation is refused before any signature is checked.
//
// XOR 0x01 does not have that property. The final character of a base64url
// segment carries slack bits that encode no byte of the payload: an Ed25519
// signature is 64 bytes, which is 86 base64url characters holding 516 bits,
// so four bits of the last character are padding. '0' XOR 0x01 is '1', and
// their six-bit values 52 and 53 differ only in those slack bits — so that
// flip would leave the signed bytes unchanged, the signature valid, and the
// sweep asserting a refusal that correctly does not happen. The sweep would
// then fail or pass according to which characters the token's base64
// happened to end with, which is a test that fails by the dice.
//
// # What stays internal, and why
//
// Three of the thirteen wire-format properties are NOT here, and their
// absence is a decision rather than an omission:
//
//   - A link whose CLAIM SET is rewritten — a widened permission set, a
//     raised ceiling, a forged par_hash, a format version this build does
//     not know. Forging one means serializing the claim set in the exact
//     member order the format fixes and re-signing it, which is knowing the
//     wire layout rather than measuring it. chain's
//     subsumption_test.go and mutation_test.go own those, and they are
//     where they belong: a suite that taught every consumer to assemble a
//     link would have published a second encoder, and a second encoder is
//     the thing that drifts.
//   - Canonicality on the way in: a caveat array out of kind order, a
//     permission list unsorted, an unmasked CIDR, a JSON member named
//     twice. Each is a non-canonical ARRIVAL, and nothing that goes through
//     Mint or Derive can produce one — they exist only if someone writes
//     the bytes directly.
//   - The decoder's own fail-closed edges, such as a registered decoder
//     that returns (nil, nil). Reaching those needs
//     caveat registration, which the package deliberately does not
//     re-export: the vocabulary is closed, and a consumer that could extend
//     it could issue tokens no other verifier understands.
//
// What a consumer CAN now assert is everything that does not require
// writing a link: the order of the links, how many there are, which chain
// they came from, and whether a single altered byte anywhere in the
// presentation is caught.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/laenenai/captoken"
)

// ---- the cases -----------------------------------------------------------

// testDepthThree is the control for every subtest in this file, and a
// property of its own: the suite's other cases derive one link, so nothing
// before this exercised a chain with an INTERIOR link — the position where
// a reordering, a drop and a splice all happen, and the position whose
// token type makes a truncated chain powerless.
func testDepthThree(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chainOfThree(t, w)

	verified, err := h.gateway.Verify(context.Background(), presented, h.request(w))
	if err != nil {
		t.Fatalf("Verify(a chain of three links) error = %v, want nil", err)
	}
	if verified.Depth != 3 {
		t.Fatalf("Depth = %d, want 3: the rest of this file positions links by index, so it needs three",
			verified.Depth)
	}
	if verified.Type != captoken.TypeExecution {
		t.Errorf("Type = %q, want %q", verified.Type, captoken.TypeExecution)
	}
	// The effective grant is the intersection of every link. Every link
	// here narrowed, so the intersection is the terminal link's — and that
	// equality is the most a consumer can observe, because a link that
	// widens cannot be signed through Mint or Derive. chain owns
	// the case where the two differ.
	if w.Wide.IsSubsetOf(verified.Permissions) {
		t.Error("the effective permission set is as wide as the root's; two derivations must have narrowed it")
	}
}

// testReorderedChain is the plainest forgery there is: the same links, in an
// order nobody signed. The suite performed no reordering at all before this.
//
// What refuses it is the cnf key chain — every link after the root must be
// signed by the key its PARENT bound, so any order but the issued one puts
// a link under a key that did not sign it — with par_hash committing each
// link to one parent's bytes behind that. A consumer cannot see which of
// the two did the work, and must not be able to: see testRefusalNamesNothing.
func testReorderedChain(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chainOfThree(t, w)
	p := measurePresentation(t, h, w, presented, 3)

	// Every order but the issued one. Three links is six permutations, so
	// this is exhaustive rather than sampled: there is nothing to bound.
	for _, order := range [][]int{
		{0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			links := make([]string, len(order))
			for i, from := range order {
				links[i] = p.links[from]
			}
			p.mustRefuse(t, h, w, p.join(links), fmt.Sprintf("the chain presented in order %v", order))
		})
	}
}

// testDroppedOrRepeatedLink covers the two ways a presentation can hold the
// right links in the right order and still not be the chain that was issued.
func testDroppedOrRepeatedLink(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chainOfThree(t, w)
	p := measurePresentation(t, h, w, presented, 3)

	for i := range p.links {
		t.Run(fmt.Sprintf("link %d dropped", i), func(t *testing.T) {
			links := slices.Delete(slices.Clone(p.links), i, i+1)
			p.mustRefuse(t, h, w, p.join(links), fmt.Sprintf("the chain with link %d removed", i))
		})
		t.Run(fmt.Sprintf("link %d repeated", i), func(t *testing.T) {
			links := slices.Insert(slices.Clone(p.links), i, p.links[i])
			p.mustRefuse(t, h, w, p.join(links), fmt.Sprintf("the chain with link %d presented twice", i))
		})
	}

	// A chain longer than the verifier's bound, which is what stops a
	// hostile presentation demanding an unbounded number of signature
	// checks before any of them has succeeded. The bound is exported, so a
	// consumer can name it; what it must not do is depend on the refusal
	// being about the length.
	long := slices.Clone(p.links)
	for len(long) <= captoken.MaxMaxLinks {
		long = append(long, p.links[len(p.links)-1])
	}
	p.mustRefuse(t, h, w, p.join(long), fmt.Sprintf("a chain of %d links", len(long)))
}

// testSplicedLink presents a link from a second, honestly minted chain in
// place of one of this chain's. Both chains are minted by the same minter
// under the same root key, so every link in the forgery carries a signature
// that verifies under SOME key the verifier trusts — which is what makes
// this a different attack from a tampered byte.
func testSplicedLink(t *testing.T, w Wiring, h *harness) {
	mine, _ := h.chainOfThree(t, w)
	theirs, _ := h.chainOfThree(t, w)
	p := measurePresentation(t, h, w, mine, 3)
	other := measurePresentation(t, h, w, theirs, 3)

	for i := range p.links {
		t.Run(fmt.Sprintf("link %d from another chain", i), func(t *testing.T) {
			links := slices.Clone(p.links)
			links[i] = other.links[i]
			p.mustRefuse(t, h, w, p.join(links),
				fmt.Sprintf("this chain with link %d taken from another chain of the same issuer", i))
		})
	}
}

// testMalformedPresentation is the fail-closed edge of the presentation
// syntax itself: a string that is not this format must be refused as
// invalid, never parsed as far as it goes.
func testMalformedPresentation(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chainOfThree(t, w)
	p := measurePresentation(t, h, w, presented, 3)
	leaf := p.links[len(p.links)-1]

	cases := map[string]string{
		"the empty string":                   "",
		"a string from an unrelated system":  "eyJhbGciOiJub25lIn0.e30.",
		"the prefix alone":                   captoken.Prefix,
		"the prefix and nothing after it":    captoken.Prefix + captoken.Separator,
		"a different presentation version":   "ct2" + captoken.Separator + strings.Join(p.links, captoken.Separator),
		"no prefix at all":                   strings.Join(p.links, captoken.Separator),
		"an empty link in the middle":        p.join([]string{p.links[0], "", p.links[1], leaf}),
		"a link with a fourth segment":       p.join([]string{p.links[0], p.links[1], leaf + ".extra"}),
		"a link with a segment missing":      p.join([]string{p.links[0], p.links[1], leaf[:strings.LastIndex(leaf, ".")]}),
		"trailing content after the chain":   presented + "tampered",
		"a separator appended to the chain":  presented + captoken.Separator,
		"whitespace padding around a prefix": " " + presented,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			p.mustRefuse(t, h, w, bad, name)
		})
	}
}

// testTruncatedPresentation sweeps the lengths a presentation can be cut to.
// Not one of them may authorise anything: a cut inside a link leaves bytes
// no signature covers, and a cut at a link boundary leaves a proper prefix,
// every one of which ends in a delegation link and authorises no operation.
//
// Sampled, not exhaustive — see this file's header comment for why, and
// presentation_test.go for the bound that keeps it a sample.
func testTruncatedPresentation(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chainOfThree(t, w)
	p := measurePresentation(t, h, w, presented, 3)

	for _, n := range p.truncationLengths() {
		if _, err := h.gateway.Verify(context.Background(), presented[:n], h.request(w)); !errors.Is(err, captoken.ErrInvalidToken) {
			t.Errorf("Verify(the chain truncated to %d of %d bytes, %s) error = %v, want wrapping ErrInvalidToken",
				n, len(presented), p.describe(n), err)
		}
	}
}

// testAlteredByte sweeps single-byte alterations of the presentation. Every
// one must be refused: the prefix and the separators are syntax, and every
// other byte is covered either by the signature over the link it is in or
// by the parent hash of the link after it.
//
// Sampled, and altered by XOR 0x20 rather than XOR 0x01 — both choices are
// explained in this file's header comment, and both matter.
func testAlteredByte(t *testing.T, w Wiring, h *harness) {
	presented, _ := h.chainOfThree(t, w)
	p := measurePresentation(t, h, w, presented, 3)

	for _, i := range p.alterPositions() {
		altered := []byte(presented)
		altered[i] ^= 0x20
		if _, err := h.gateway.Verify(context.Background(), string(altered), h.request(w)); !errors.Is(err, captoken.ErrInvalidToken) {
			t.Errorf("Verify(the chain with byte %d of %d altered, %s) error = %v, want wrapping ErrInvalidToken",
				i, len(presented), p.describe(i), err)
		}
	}
}

// ---- the measurement -----------------------------------------------------

// presentation is a presented chain split into its links, with the split
// checked against the implementation's own report of the chain's shape. See
// this file's header comment for why it is measured rather than assumed.
type presentation struct {
	// prefix is everything before the first link, the separator included.
	prefix string
	// links are the compact links, root first.
	links []string
	// starts[i] is the byte offset at which link i begins, and dots[i] are
	// the offsets of link i's two dots, measured from the link's own bytes.
	starts []int
	dots   [][]int
	// total is the presentation's length in bytes.
	total int
}

// measurePresentation splits presented into its links and checks the split.
//
// wantDepth is what the caller built, and the check that the verifier
// agrees is the measurement: Verify fills Depth in from the chain it walked,
// so a split that produced a different count means this helper is counting
// something other than links and every offset below is meaningless.
func measurePresentation(t *testing.T, h *harness, w Wiring, presented string, wantDepth int) presentation {
	t.Helper()

	prefix := captoken.Prefix + captoken.Separator
	rest, ok := strings.CutPrefix(presented, prefix)
	if !ok {
		t.Fatalf("the presentation %q does not start with %q, so it is not this format and no offset in it can be positioned",
			truncateForMessage(presented), prefix)
	}
	p := presentation{prefix: prefix, links: strings.Split(rest, captoken.Separator), total: len(presented)}

	verified, err := h.gateway.Verify(context.Background(), presented, h.request(w))
	if err != nil {
		t.Fatalf("the presentation this subtest is about to tamper with does not verify untampered: %v\n"+
			"every assertion below is that a TAMPERED chain is refused, and all of them would pass just as "+
			"well if the honest one were refused too", err)
	}
	if verified.Depth != len(p.links) {
		t.Fatalf("the presentation splits into %d links on %q, but the verifier walked %d: "+
			"the split is not finding links, so no offset computed from it means anything",
			len(p.links), captoken.Separator, verified.Depth)
	}
	if verified.Depth != wantDepth {
		t.Fatalf("Depth = %d, want %d: this subtest positions links by index", verified.Depth, wantDepth)
	}

	off := len(prefix)
	for _, link := range p.links {
		if link == "" {
			t.Fatalf("link %d of the honest presentation is empty", len(p.starts))
		}
		p.starts = append(p.starts, off)
		// A link is a compact JWS: exactly three dot-separated segments.
		// The boundaries come from the link's own dots, so nothing here
		// assumes what a segment holds.
		var dots []int
		for i, b := range []byte(link) {
			if b == '.' {
				dots = append(dots, off+i)
			}
		}
		if len(dots) != 2 {
			t.Fatalf("link %d has %d dots, want 2: a link is a compact JWS with three segments, and "+
				"docs/wire-format.md publishes that", len(p.starts)-1, len(dots))
		}
		p.dots = append(p.dots, dots)
		off += len(link) + len(captoken.Separator)
	}
	return p
}

// join assembles a presentation from links, using the syntax the exported
// constants publish.
func (p presentation) join(links []string) string {
	return p.prefix + strings.Join(links, captoken.Separator)
}

// mustRefuse fails unless the verifier refuses presented as an invalid
// token.
//
// It requires only ErrInvalidToken, never a more specific cause, and that is
// the error discipline rather than a weak assertion: a verifier that said
// WHICH of a dozen checks a forgery failed would have handed the forger a
// dimension to search along. See testRefusalNamesNothing.
func (p presentation) mustRefuse(t *testing.T, h *harness, w Wiring, presented, what string) {
	t.Helper()
	if _, err := h.gateway.Verify(context.Background(), presented, h.request(w)); !errors.Is(err, captoken.ErrInvalidToken) {
		t.Errorf("Verify(%s) error = %v, want wrapping ErrInvalidToken", what, err)
	}
}

// segmentBounds returns the offsets at which link i's three segments begin
// and the offset one past its last byte.
func (p presentation) segmentBounds(i int) (bounds []int) {
	end := p.starts[i] + len(p.links[i])
	return []int{p.starts[i], p.dots[i][0] + 1, p.dots[i][1] + 1, end}
}

// alterPositions returns the byte positions the alteration sweep samples,
// sorted and without duplicates. Every byte of the prefix and every
// separator is included because they are the syntax, they are few, and they
// are the one region no signature covers directly; within a link the sample
// is each dot and each segment's first and last byte, plus a couple of
// interior offsets that -short drops.
func (p presentation) alterPositions() []int {
	var positions []int
	for i := range len(p.prefix) {
		positions = append(positions, i)
	}
	for i := range p.links {
		if i > 0 {
			positions = append(positions, p.starts[i]-len(captoken.Separator))
		}
		positions = append(positions, p.dots[i]...)
		bounds := p.segmentBounds(i)
		for s := range 3 {
			start, end := bounds[s], bounds[s+1]
			if s < 2 {
				end-- // the dot, which is sampled on its own
			}
			positions = append(positions, start, end-1)
			if !testing.Short() && end-start > 4 {
				positions = append(positions, start+(end-start)/2)
			}
		}
	}
	return clamped(positions, p.total)
}

// truncationLengths returns the lengths the truncation sweep samples: the
// syntax's own edges, and on, just before and just after every link
// boundary, which is where a length-handling bug lives. A truncation to
// exactly a link boundary is a proper prefix of the chain, which
// testTruncationAuthorisesNothing also asserts on its own so the property
// has a name in test output rather than only a position in a loop.
func (p presentation) truncationLengths() []int {
	positions := []int{0, 1, len(p.prefix) - 1, len(p.prefix), len(p.prefix) + 1, p.total - 1}
	for i := range p.links {
		start := p.starts[i]
		positions = append(positions, start-1, start, start+1)
		if !testing.Short() {
			positions = append(positions, start+len(p.links[i])/2)
		}
	}
	return clamped(positions, p.total)
}

// describe names the region a byte offset falls in, so a failure message
// says "link 1, segment 2" rather than only a number.
func (p presentation) describe(off int) string {
	if off < len(p.prefix) {
		return fmt.Sprintf("in the %d-byte prefix", len(p.prefix))
	}
	for i := range p.links {
		if i > 0 && off == p.starts[i]-len(captoken.Separator) {
			return fmt.Sprintf("the separator before link %d", i)
		}
		bounds := p.segmentBounds(i)
		if off < bounds[0] || off >= bounds[3] {
			continue
		}
		for s := range 3 {
			if off < bounds[s+1] {
				return fmt.Sprintf("in link %d of %d, segment %d of 3", i, len(p.links), s+1)
			}
		}
	}
	return "past the end of the chain"
}

// clamped sorts positions, drops duplicates and drops anything outside
// [0, total). It builds a new slice rather than filtering in place: an
// in-place filter would overwrite the element the duplicate check compares
// against.
func clamped(positions []int, total int) []int {
	sort.Ints(positions)
	out := make([]int, 0, len(positions))
	for i, pos := range positions {
		if pos < 0 || pos >= total {
			continue
		}
		if i > 0 && pos == positions[i-1] {
			continue
		}
		out = append(out, pos)
	}
	return out
}

// truncateForMessage bounds a string put into a failure message, so a
// malformed presentation of any size does not flood the output.
func truncateForMessage(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
