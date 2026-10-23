package domain

import (
	"fmt"
	"unicode/utf8"
)

// ErrMalformedResourceSchema is returned by NewResourceSchema, and by any
// method of the zero ResourceSchema, when a consumer's declared resource
// hierarchy is not usable: no levels, an empty or duplicated level name, or
// a name that is not valid UTF-8.
var ErrMalformedResourceSchema = newSentinel("malformed resource schema")

// ErrMalformedResourcePath is returned by ResourceSchema.Path when the
// segments given do not form a path the declared hierarchy allows.
var ErrMalformedResourcePath = newSentinel("malformed resource path")

// ErrUnresolvedResourcePath is returned by ResourcePath.Contains when
// either side was never constructed through a ResourceSchema — the zero
// value, which a bare struct literal produces.
//
// The direction matters, and it is the same ruling cas's
// domain.ErrUnresolvedResourceRef records: a caller must treat this as a
// reason to refuse, never as "this path contains nothing, so no scope
// applies". Those are indistinguishable from the outside and only one of
// them is safe.
var ErrUnresolvedResourcePath = newSentinel("unresolved resource path")

// Segment is one (kind, id) step of a ResourcePath: a level of the
// consumer's hierarchy and the opaque identifier of the node at that level.
// Both halves are opaque to this module — it never interprets an id, and a
// kind name is only ever compared for equality against the schema that
// declared it.
type Segment struct {
	// Kind names the level, and must be one this path's schema declared.
	Kind string
	// ID identifies the node at that level. It is opaque, non-empty, and
	// compared only for exact equality.
	ID string
}

// SegmentKind declares one level of a consumer's resource hierarchy, in the
// order NewResourceSchema receives them: outermost first.
type SegmentKind struct {
	// Name is the level's wire name. It appears verbatim in a token's
	// "res" claim, so it is part of the published format for whoever
	// registered it — see docs/wire-format.md.
	Name string
	// Repeats reports whether this level may nest within itself, zero or
	// more times. CAS's filesets do; its tenants and documents do not.
	//
	// A repeating level is therefore also an optional one: zero
	// repetitions is allowed, so a document filed directly under its
	// tenant is a well-formed path. A non-repeating level may be absent
	// only if every level after it is also absent — a path stops where the
	// resource stops, but it never skips a rung with something hanging
	// below it.
	Repeats bool
}

// ResourceSchema is the consumer's declared resource hierarchy: the one
// thing this module needs to know about a consumer's resource model, and
// deliberately the only thing.
//
// # Why a declared schema, and not an interface the consumer implements
//
// The charter requires this module to work as a service for verifiers that
// are not this module and are not Go. Containment is a security-relevant
// comparison, so it has to be performed identically by a Python verifier at
// another organisation's trust boundary. An interface a consumer implements
// in Go cannot be run there; a documented data shape plus a documented
// algorithm can. So the resource model is *data* a consumer declares, the
// containment rule is this module's and is published, and the consumer's
// own domain type maps onto a ResourcePath at its own boundary with an
// ordinary function — no interface, no registration of behaviour, nothing
// of the consumer's semantics inside this module.
//
// # Why segments, and not a flattened string
//
// The Biscuit spike demonstrated the alternative failing: flattening a
// structured reference into one string makes containment a string prefix
// test, which matched the scope "fs/a" against its sibling "fs/ab". Keeping
// the path as a sequence of segments makes containment a segment-wise
// comparison, and a sibling can never satisfy it, because "a" and "ab" are
// different strings rather than one being a prefix of the other. There is
// no separator to canonicalize, terminate or escape, so there is no
// security-critical encoding to get right.
//
// A ResourceSchema is a value, passed in configuration rather than
// registered globally, so two consumers linked into one process cannot
// collide.
type ResourceSchema struct {
	kinds []SegmentKind
}

// NewResourceSchema declares a resource hierarchy, outermost level first.
func NewResourceSchema(kinds ...SegmentKind) (ResourceSchema, error) {
	if len(kinds) == 0 {
		return ResourceSchema{}, fmt.Errorf("%w: no levels declared", ErrMalformedResourceSchema)
	}
	seen := make(map[string]struct{}, len(kinds))
	for _, k := range kinds {
		if k.Name == "" {
			return ResourceSchema{}, fmt.Errorf("%w: a level name is empty", ErrMalformedResourceSchema)
		}
		if !utf8.ValidString(k.Name) {
			return ResourceSchema{}, fmt.Errorf("%w: a level name is not valid UTF-8", ErrMalformedResourceSchema)
		}
		if _, dup := seen[k.Name]; dup {
			return ResourceSchema{}, fmt.Errorf("%w: a level name is declared twice", ErrMalformedResourceSchema)
		}
		seen[k.Name] = struct{}{}
	}
	return ResourceSchema{kinds: append([]SegmentKind(nil), kinds...)}, nil
}

// IsZero reports whether s is the zero ResourceSchema, which declares
// nothing and constructs nothing.
func (s ResourceSchema) IsZero() bool { return len(s.kinds) == 0 }

// Kinds returns the declared levels, outermost first.
func (s ResourceSchema) Kinds() []SegmentKind {
	return append([]SegmentKind(nil), s.kinds...)
}

// Path validates segs against the declared hierarchy and returns the
// resulting ResourcePath. It is the only way to obtain a usable
// ResourcePath, which is what makes a decoded path well-formed by
// construction: the encoder refuses anything the schema does not accept, so
// nothing malformed ever reaches the wire for a decoder to have to
// second-guess.
func (s ResourceSchema) Path(segs ...Segment) (ResourcePath, error) {
	if s.IsZero() {
		return ResourcePath{}, fmt.Errorf("%w: no levels declared", ErrMalformedResourceSchema)
	}
	if len(segs) == 0 {
		return ResourcePath{}, fmt.Errorf("%w: no segments", ErrMalformedResourcePath)
	}
	for _, seg := range segs {
		if seg.ID == "" {
			return ResourcePath{}, fmt.Errorf("%w: a segment id is empty", ErrMalformedResourcePath)
		}
		if !utf8.ValidString(seg.ID) {
			return ResourcePath{}, fmt.Errorf("%w: a segment id is not valid UTF-8", ErrMalformedResourcePath)
		}
	}

	// Walk the declared levels and the given segments together. Each
	// declared level consumes one segment, or zero-or-more when it
	// repeats; a level that consumes nothing is allowed only if nothing
	// after it is present either, so a path may stop short of the leaf but
	// never skip a rung it is still hanging something below.
	i := 0
	skipped := false
	for _, kind := range s.kinds {
		if i < len(segs) && segs[i].Kind == kind.Name {
			if skipped {
				return ResourcePath{}, fmt.Errorf("%w: a level is skipped but a deeper one is present", ErrMalformedResourcePath)
			}
			i++
			if kind.Repeats {
				for i < len(segs) && segs[i].Kind == kind.Name {
					i++
				}
			}
			continue
		}
		if !kind.Repeats {
			skipped = true
		}
	}
	if i != len(segs) {
		return ResourcePath{}, fmt.Errorf("%w: segment %d is not a declared level in declared order", ErrMalformedResourcePath, i)
	}

	return ResourcePath{segs: append([]Segment(nil), segs...)}, nil
}

// ResourcePath is one validated node of a consumer's resource hierarchy:
// an ordered sequence of segments from the outermost level inwards.
//
// It is deliberately opaque. There is no exported field to populate, no
// UnmarshalJSON and no sql.Scanner, because every one of those would let a
// path come into existence without passing its schema — and a path that
// never passed its schema is exactly what cas's "resolved" flag existed to
// catch. The zero value is the one unvalidated form, and it fails closed
// everywhere.
type ResourcePath struct {
	segs []Segment
}

// Valid reports whether p was constructed through a ResourceSchema. The
// zero ResourcePath is not.
func (p ResourcePath) Valid() bool { return len(p.segs) > 0 }

// Segments returns a copy of p's segments, outermost first.
func (p ResourcePath) Segments() []Segment {
	return append([]Segment(nil), p.segs...)
}

// Contains reports whether p contains other: either p IS other, or other
// sits beneath p in the hierarchy. Containment is reflexive, so a scope
// placed at a level applies to that level and everything nested within it.
//
// The comparison is segment-wise: p contains other exactly when p's
// segments are an element-wise prefix of other's, comparing each (kind, id)
// pair for exact equality. It is never a string prefix test — see
// ResourceSchema's doc comment for the bug that distinction prevents.
//
// An unvalidated path on either side returns ErrUnresolvedResourcePath
// rather than false. See that error's doc comment for why the difference
// matters.
func (p ResourcePath) Contains(other ResourcePath) (bool, error) {
	if !p.Valid() || !other.Valid() {
		return false, ErrUnresolvedResourcePath
	}
	if len(p.segs) > len(other.segs) {
		return false, nil
	}
	for i := range p.segs {
		if p.segs[i] != other.segs[i] {
			return false, nil
		}
	}
	return true, nil
}

// Equal reports whether p and other are the same path. Two unvalidated
// paths are never equal, since neither names anything.
func (p ResourcePath) Equal(other ResourcePath) bool {
	if !p.Valid() || !other.Valid() || len(p.segs) != len(other.segs) {
		return false
	}
	for i := range p.segs {
		if p.segs[i] != other.segs[i] {
			return false
		}
	}
	return true
}
