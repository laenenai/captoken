package captoken_test

import (
	"testing"

	"github.com/laenenai/captoken"
	"github.com/laenenai/captoken/captokentest"
)

// TestSuiteAgainstTheInMemoryWiring runs the module's own conformance suite
// against the in-memory adapters and against CAS's resource hierarchy,
// which is the schema the extracted caveat semantics were written for.
//
// It is the module's own evidence that the suite is runnable and passes;
// CHARTER.md's adoption test is a CONSUMER running the same suite against
// its own wiring, which this cannot stand in for.
func TestSuiteAgainstTheInMemoryWiring(t *testing.T) {
	t.Parallel()

	captokentest.RunCapabilitySuite(t, func(t *testing.T) captokentest.Wiring {
		schema, err := captoken.NewResourceSchema(
			captoken.SegmentKind{Name: "tenant"},
			captoken.SegmentKind{Name: "fileset", Repeats: true},
			captoken.SegmentKind{Name: "document"},
			captoken.SegmentKind{Name: "slot"},
			captoken.SegmentKind{Name: "element"},
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
		return captokentest.Wiring{
			Schema: schema,
			Outer:  path(seg("tenant", "t1"), seg("fileset", "a")),
			Inner:  path(seg("tenant", "t1"), seg("fileset", "a"), seg("document", "d1")),
			// "ab", not "b": a sibling whose identifier shares a prefix
			// with one in scope is the case a flattened scope string gets
			// wrong, and the one the Biscuit spike demonstrated failing.
			Sibling:     path(seg("tenant", "t1"), seg("fileset", "ab"), seg("document", "d1")),
			Wide:        captoken.NewPermissionSet("doc.read_content", "doc.write_content", "doc.tag"),
			Narrow:      captoken.NewPermissionSet("doc.read_content"),
			Exercised:   "doc.read_content",
			Counters:    memory,
			Revocations: memory,
			Nonces:      memory,
		}
	})
}
