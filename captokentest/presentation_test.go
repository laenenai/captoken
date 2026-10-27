package captokentest

// The self-test for presentation.go. Three things need pinning, and none of
// them is pinned by the conformance subtests themselves.
//
// First, that the measurement is right rather than merely self-consistent. A
// split that found the wrong boundaries and then positioned offsets inside
// them would agree with itself; these tests check it against what
// docs/wire-format.md states for presentation version 1 — the prefix "ct1",
// the separator "~", and a link that is a compact JWS with three segments.
//
// Second, that the sweeps stay samples. presentation.go's header comment
// asks the next reader not to turn them into exhaustive loops, and a comment
// is not an enforcement mechanism: TestAlterPositions_StayASample fails if
// the sample grows past a bound no sampled sweep needs, which is what an
// exhaustive rewrite looks like from here.
//
// Third, that the sample still covers the positions it claims to. A bound on
// the count alone would be satisfied by a sweep that had quietly stopped
// sampling anything structural.

import (
	"strings"
	"testing"

	"github.com/laenenai/captoken"
)

// The presentation syntax as docs/wire-format.md publishes it. The constants
// are duplicated here rather than read from the facade on purpose: the point
// of the test is to compare the measurement against the document, and
// comparing captoken.Prefix against captoken.Prefix would compare the code
// against itself.
const (
	documentedPrefix       = "ct1"
	documentedSeparator    = "~"
	documentedLinkSegments = 3
)

// selfTestWiring is the in-memory wiring these self-tests measure against.
// It is the same hierarchy suite_test.go uses, declared again here because a
// self-test that imported the module's own test fixtures would be one more
// thing to keep in step.
func selfTestWiring(t *testing.T) Wiring {
	t.Helper()

	schema, err := captoken.NewResourceSchema(
		captoken.SegmentKind{Name: "tenant"},
		captoken.SegmentKind{Name: "fileset", Repeats: true},
		captoken.SegmentKind{Name: "document"},
	)
	if err != nil {
		t.Fatalf("NewResourceSchema() error = %v", err)
	}
	path := func(segs ...captoken.Segment) captoken.ResourcePath {
		p, perr := schema.Path(segs...)
		if perr != nil {
			t.Fatalf("Path() error = %v", perr)
		}
		return p
	}
	seg := func(kind, id string) captoken.Segment {
		return captoken.Segment{Kind: kind, ID: id}
	}

	memory := captoken.NewMemory()
	return Wiring{
		Schema:      schema,
		Outer:       path(seg("tenant", "t1"), seg("fileset", "a")),
		Inner:       path(seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
		Sibling:     path(seg("tenant", "t1"), seg("fileset", "ab"), seg("document", "d1")),
		Wide:        captoken.NewPermissionSet("doc.read", "doc.write", "doc.tag"),
		Narrow:      captoken.NewPermissionSet("doc.read"),
		Exercised:   "doc.read",
		Counters:    memory,
		Revocations: memory,
		Nonces:      memory,
	}
}

// measuredChain returns a measured three-link presentation and the harness it
// was minted by.
func measuredChain(t *testing.T) (presentation, *harness, Wiring) {
	t.Helper()
	w := selfTestWiring(t)
	h := newHarness(t, w)
	presented, _ := h.chainOfThree(t, w)
	return measurePresentation(t, h, w, presented, 3), h, w
}

func TestMeasurePresentation_AgreesWithTheFormatDocument(t *testing.T) {
	t.Parallel()

	p, _, _ := measuredChain(t)

	if want := documentedPrefix + documentedSeparator; p.prefix != want {
		t.Errorf("measured prefix = %q, want %q (docs/wire-format.md's presentation syntax)", p.prefix, want)
	}
	if len(p.links) != 3 {
		t.Fatalf("measured %d links, want 3", len(p.links))
	}
	for i, link := range p.links {
		if got := strings.Count(link, "."); got != documentedLinkSegments-1 {
			t.Errorf("link %d has %d dots, want %d: a link is a compact JWS",
				i, got, documentedLinkSegments-1)
		}
		if p.starts[i] != len(p.prefix)+offsetOfLink(p, i) {
			t.Errorf("link %d starts at %d, which is not where joining the links before it puts it", i, p.starts[i])
		}
	}
	if p.total != len(p.join(p.links)) {
		t.Errorf("total = %d, but rejoining the measured links gives %d bytes: the split is lossy",
			p.total, len(p.join(p.links)))
	}
}

// offsetOfLink recomputes link i's offset from the links before it, which is
// the independent check that starts[] was not filled in from the offsets it
// is supposed to have derived.
func offsetOfLink(p presentation, i int) int {
	off := 0
	for _, link := range p.links[:i] {
		off += len(link) + len(documentedSeparator)
	}
	return off
}

// maxSampledPositions is the bound that keeps a sample a sample. The sweep
// draws every prefix byte, one per separator, and at most eleven positions
// per link, so three links is at most 40; anything approaching the
// presentation's two thousand bytes is an exhaustive rewrite, which
// presentation.go's header comment explains must not happen.
const maxSampledPositions = 80

func TestAlterPositions_StayASample(t *testing.T) {
	t.Parallel()

	p, _, _ := measuredChain(t)
	positions := p.alterPositions()

	if len(positions) > maxSampledPositions {
		t.Fatalf("alterPositions returned %d of %d byte positions, past the %d a sampled sweep needs: "+
			"an alteration at every position of a 2 kB presentation is the same signature check two "+
			"thousand times, which is why this is sampled", len(positions), p.total, maxSampledPositions)
	}

	have := make(map[int]bool, len(positions))
	for _, pos := range positions {
		have[pos] = true
	}
	for i := range len(p.prefix) {
		if !have[i] {
			t.Errorf("prefix byte %d is not sampled; the prefix is the syntax and no signature covers it", i)
		}
	}
	for i := range p.links {
		if i > 0 {
			if sep := p.starts[i] - len(documentedSeparator); !have[sep] {
				t.Errorf("the separator before link %d (offset %d) is not sampled", i, sep)
			}
		}
		for _, dot := range p.dots[i] {
			if !have[dot] {
				t.Errorf("link %d: the dot at offset %d is not sampled", i, dot)
			}
		}
		bounds := p.segmentBounds(i)
		for s := range documentedLinkSegments {
			for name, pos := range map[string]int{
				"its first byte": bounds[s],
				"its last byte":  bounds[s+1] - 1,
			} {
				if !have[pos] {
					t.Errorf("link %d, segment %d: %s (offset %d) is not sampled", i, s+1, name, pos)
				}
			}
		}
	}
}

func TestTruncationLengths_StayASampleAndIncludeEveryLinkBoundary(t *testing.T) {
	t.Parallel()

	p, _, _ := measuredChain(t)
	lengths := p.truncationLengths()

	if len(lengths) > maxSampledPositions {
		t.Fatalf("truncationLengths returned %d of %d lengths, past the %d a sampled sweep needs",
			len(lengths), p.total, maxSampledPositions)
	}

	have := make(map[int]bool, len(lengths))
	for _, n := range lengths {
		have[n] = true
	}
	for i := range p.links {
		// The length at which exactly the links before i are left: a proper
		// prefix of the chain, which must authorise nothing. Without it the
		// sampled sweep would be weaker than ATruncatedChainAuthorisesNothing
		// rather than a superset of it.
		if boundary := p.starts[i]; !have[boundary] {
			t.Errorf("no sampled truncation length is %d, the length at which link %d and everything "+
				"after it is gone", boundary, i)
		}
	}
}

// TestAlterPositions_AlwaysChangeTheSignedBytes is why the sweep flips 0x20
// and not 0x01.
//
// Flipping the ASCII case bit either leaves the base64url alphabet — so the
// presentation is refused before a signature is checked — or maps a letter to
// the letter of the other case, whose six-bit value differs in its top two
// bits, so the decoded bytes differ and the signature over them fails.
// Flipping 0x01 does neither at the final character of a segment, where four
// bits encode nothing: '0' and '1' decode to the same bytes, and a sweep
// built on that flip would assert a refusal that correctly does not happen,
// failing or passing according to what the token's base64 happened to end
// with. This test pins the claim about the two flips rather than leaving it
// as a comment.
func TestAlterPositions_AlwaysChangeTheSignedBytes(t *testing.T) {
	t.Parallel()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	value := func(c byte) int { return strings.IndexByte(alphabet, c) }

	caseFlipSurvives, oneFlipSurvives := 0, 0
	for i := range len(alphabet) {
		c := alphabet[i]
		for _, flip := range []struct {
			mask byte
			hits *int
		}{{0x20, &caseFlipSurvives}, {0x01, &oneFlipSurvives}} {
			other := value(c ^ flip.mask)
			if other < 0 {
				continue // outside the alphabet: refused before any signature check
			}
			if value(c)>>4 == other>>4 {
				// Same top two bits: at a segment's final character, where
				// the low four bits encode nothing, this flip leaves the
				// signed bytes untouched.
				*flip.hits++
			}
		}
	}
	if caseFlipSurvives != 0 {
		t.Errorf("%d base64url characters keep their top two bits under XOR 0x20; the sweep's flip must "+
			"always change the signed bytes or leave the alphabet", caseFlipSurvives)
	}
	if oneFlipSurvives == 0 {
		t.Error("no base64url character keeps its top two bits under XOR 0x01, so the reason " +
			"presentation.go gives for not using that flip no longer holds and the comment should be " +
			"corrected rather than trusted")
	}
}
