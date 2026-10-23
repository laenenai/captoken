package domain_test

import (
	"errors"
	"testing"

	"github.com/laenenai/captoken/internal/domain"
)

// casSchema is the resource hierarchy CAS registers, used throughout these
// tests because the ported cases from cas/internal/token/caveat_test.go are
// expressed against it: tenant > fileset (nestable) > document > slot >
// slot element.
func casSchema(t *testing.T) domain.ResourceSchema {
	t.Helper()
	s, err := domain.NewResourceSchema(
		domain.SegmentKind{Name: "tenant"},
		domain.SegmentKind{Name: "fileset", Repeats: true},
		domain.SegmentKind{Name: "document"},
		domain.SegmentKind{Name: "slot"},
		domain.SegmentKind{Name: "element"},
	)
	if err != nil {
		t.Fatalf("NewResourceSchema() error = %v, want nil", err)
	}
	return s
}

func mustPath(t *testing.T, s domain.ResourceSchema, segs ...domain.Segment) domain.ResourcePath {
	t.Helper()
	p, err := s.Path(segs...)
	if err != nil {
		t.Fatalf("Path(%v) error = %v, want nil", segs, err)
	}
	return p
}

func TestResourceSchema_RejectsAnEmptyOrMalformedDeclaration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		kinds []domain.SegmentKind
	}{
		{"no kinds at all", nil},
		{"an empty kind name", []domain.SegmentKind{{Name: ""}}},
		{"a duplicated kind name", []domain.SegmentKind{{Name: "tenant"}, {Name: "tenant"}}},
		{"a kind name that is not valid UTF-8", []domain.SegmentKind{{Name: "\xff"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.NewResourceSchema(tc.kinds...); !errors.Is(err, domain.ErrMalformedResourceSchema) {
				t.Errorf("NewResourceSchema() error = %v, want wrapping ErrMalformedResourceSchema", err)
			}
		})
	}
}

func TestResourceSchema_AcceptsEveryPathTheHierarchyAllows(t *testing.T) {
	t.Parallel()
	s := casSchema(t)

	cases := [][]domain.Segment{
		{{Kind: "tenant", ID: "t1"}},
		{{Kind: "tenant", ID: "t1"}, {Kind: "fileset", ID: "a"}},
		{{Kind: "tenant", ID: "t1"}, {Kind: "fileset", ID: "a"}, {Kind: "fileset", ID: "b"}},
		{{Kind: "tenant", ID: "t1"}, {Kind: "document", ID: "d1"}},
		{{Kind: "tenant", ID: "t1"}, {Kind: "fileset", ID: "a"}, {Kind: "document", ID: "d1"}},
		{
			{Kind: "tenant", ID: "t1"},
			{Kind: "document", ID: "d1"},
			{Kind: "slot", ID: "pages"},
			{Kind: "element", ID: "3"},
		},
	}
	for _, segs := range cases {
		if _, err := s.Path(segs...); err != nil {
			t.Errorf("Path(%v) error = %v, want nil", segs, err)
		}
	}
}

// TestResourceSchema_RefusesAPathTheHierarchyDoesNotAllow is the mint-time
// half of the fail-closed guard cas spelled as domain.ResourceRef's
// "resolved" flag plus encodeResource's refusal: nothing malformed may ever
// reach the wire, which is what lets the decoder treat a decoded path as
// well-formed by construction.
func TestResourceSchema_RefusesAPathTheHierarchyDoesNotAllow(t *testing.T) {
	t.Parallel()
	s := casSchema(t)

	cases := []struct {
		name string
		segs []domain.Segment
	}{
		{"no segments", nil},
		{"an undeclared kind", []domain.Segment{{Kind: "bucket", ID: "b"}}},
		{"not starting at the root kind", []domain.Segment{{Kind: "document", ID: "d1"}}},
		{
			"out of declared order",
			[]domain.Segment{{Kind: "tenant", ID: "t1"}, {Kind: "slot", ID: "pages"}, {Kind: "document", ID: "d1"}},
		},
		{
			"skipping a non-repeating level that something follows",
			[]domain.Segment{{Kind: "tenant", ID: "t1"}, {Kind: "slot", ID: "pages"}},
		},
		{
			"a repeated non-repeating level",
			[]domain.Segment{{Kind: "tenant", ID: "t1"}, {Kind: "tenant", ID: "t2"}},
		},
		{"an empty id", []domain.Segment{{Kind: "tenant", ID: ""}}},
		{"an id that is not valid UTF-8", []domain.Segment{{Kind: "tenant", ID: "\xff\xfe"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := s.Path(tc.segs...); !errors.Is(err, domain.ErrMalformedResourcePath) {
				t.Errorf("Path(%v) error = %v, want wrapping ErrMalformedResourcePath", tc.segs, err)
			}
		})
	}
}

// TestResourcePath_ContainsIsSegmentWiseNeverAStringPrefix is the test the
// Biscuit spike's finding demands. Flattening a structured reference to a
// string makes containment a .starts_with, which the spike demonstrated
// matching scope "fs/a" against its sibling "fs/ab". Segment-wise equality
// cannot produce that, and this test is what keeps the comparison
// structured.
func TestResourcePath_ContainsIsSegmentWiseNeverAStringPrefix(t *testing.T) {
	t.Parallel()
	s := casSchema(t)

	scope := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t1"}, domain.Segment{Kind: "fileset", ID: "a"})
	sibling := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t1"}, domain.Segment{Kind: "fileset", ID: "ab"})

	contains, err := scope.Contains(sibling)
	if err != nil {
		t.Fatalf("Contains() error = %v, want nil", err)
	}
	if contains {
		t.Error("scope fileset \"a\" contains sibling fileset \"ab\": containment has been flattened to a string prefix")
	}

	// And a genuine descendant is still contained.
	nested := mustPath(t, s,
		domain.Segment{Kind: "tenant", ID: "t1"},
		domain.Segment{Kind: "fileset", ID: "a"},
		domain.Segment{Kind: "fileset", ID: "b"},
		domain.Segment{Kind: "document", ID: "d1"},
	)
	if contains, err = scope.Contains(nested); err != nil || !contains {
		t.Errorf("Contains(nested) = (%v, %v), want (true, nil)", contains, err)
	}
}

func TestResourcePath_ContainsIsReflexiveAndHierarchical(t *testing.T) {
	t.Parallel()
	s := casSchema(t)

	tenant := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t1"})
	doc1 := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t1"}, domain.Segment{Kind: "document", ID: "d1"})
	doc2 := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t1"}, domain.Segment{Kind: "document", ID: "d2"})
	otherTenant := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t2"}, domain.Segment{Kind: "document", ID: "d1"})
	slot := mustPath(t, s,
		domain.Segment{Kind: "tenant", ID: "t1"}, domain.Segment{Kind: "document", ID: "d1"},
		domain.Segment{Kind: "slot", ID: "pages"},
	)
	element := mustPath(t, s,
		domain.Segment{Kind: "tenant", ID: "t1"}, domain.Segment{Kind: "document", ID: "d1"},
		domain.Segment{Kind: "slot", ID: "pages"}, domain.Segment{Kind: "element", ID: "3"},
	)

	cases := []struct {
		name  string
		outer domain.ResourcePath
		inner domain.ResourcePath
		want  bool
	}{
		{"reflexive", doc1, doc1, true},
		{"tenant contains a document", tenant, doc1, true},
		{"a document does not contain its tenant", doc1, tenant, false},
		{"a document does not contain a sibling", doc1, doc2, false},
		{"another tenant's document is outside", tenant, otherTenant, false},
		{"a slot series contains one of its elements", slot, element, true},
		{"an element does not contain its series", element, slot, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.outer.Contains(tc.inner)
			if err != nil {
				t.Fatalf("Contains() error = %v, want nil", err)
			}
			if got != tc.want {
				t.Errorf("Contains() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResourcePath_ZeroValueRefusesRatherThanContainsNothing ports
// cas's TestResourceScope_RefusesRatherThanIgnoresUnresolvedRequestResource.
// A bare struct literal is the pervasive, easy mistake; it must be
// distinguishable from a validated path that genuinely names a root, and it
// must fail closed in BOTH directions rather than quietly meaning "contains
// nothing" or "is contained by nothing".
func TestResourcePath_ZeroValueRefusesRatherThanContainsNothing(t *testing.T) {
	t.Parallel()
	s := casSchema(t)
	real := mustPath(t, s, domain.Segment{Kind: "tenant", ID: "t1"})

	var zero domain.ResourcePath
	if zero.Valid() {
		t.Error("the zero ResourcePath reports Valid")
	}
	if _, err := zero.Contains(real); !errors.Is(err, domain.ErrUnresolvedResourcePath) {
		t.Errorf("zero.Contains(real) error = %v, want wrapping ErrUnresolvedResourcePath", err)
	}
	if _, err := real.Contains(zero); !errors.Is(err, domain.ErrUnresolvedResourcePath) {
		t.Errorf("real.Contains(zero) error = %v, want wrapping ErrUnresolvedResourcePath", err)
	}
}

// TestResourcePath_SegmentsAreCopiedNotAliased keeps a validated path
// immutable: a caller that mutates the slice it got back, or the slice it
// passed in, must not be able to change what a path means after it has been
// checked.
func TestResourcePath_SegmentsAreCopiedNotAliased(t *testing.T) {
	t.Parallel()
	s := casSchema(t)

	in := []domain.Segment{{Kind: "tenant", ID: "t1"}, {Kind: "document", ID: "d1"}}
	p, err := s.Path(in...)
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}
	in[1].ID = "d-ELSEWHERE"
	if got := p.Segments()[1].ID; got != "d1" {
		t.Errorf("mutating the input slice changed the path: segment id = %q, want %q", got, "d1")
	}

	out := p.Segments()
	out[1].ID = "d-ELSEWHERE"
	if got := p.Segments()[1].ID; got != "d1" {
		t.Errorf("mutating the returned slice changed the path: segment id = %q, want %q", got, "d1")
	}
}

func TestResourceSchema_ZeroValueConstructsNothing(t *testing.T) {
	t.Parallel()

	var zero domain.ResourceSchema
	if !zero.IsZero() {
		t.Error("the zero ResourceSchema does not report IsZero")
	}
	if _, err := zero.Path(domain.Segment{Kind: "tenant", ID: "t1"}); !errors.Is(err, domain.ErrMalformedResourceSchema) {
		t.Errorf("zero.Path() error = %v, want wrapping ErrMalformedResourceSchema", err)
	}
}
