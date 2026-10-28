package caveat_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
)

// allKinds returns one caveat of every registered kind, for the codec's
// table tests. It is deliberately a different list from narrowsTable's, so
// a kind added to one and not the other is caught by the count assertions
// in both.
func allKinds(t *testing.T) []caveat.Caveat {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	return []caveat.Caveat{
		caveat.ExpiresAt(now),
		caveat.NotBefore(now.Add(-time.Hour)),
		caveat.ExpiresAfterFirstUse(90 * time.Second),
		caveat.MaxUses(3),
		caveat.ResourceScope{Scopes: []domain.ResourcePath{doc1(t)}},
		caveat.PermissionSet(domain.NewPermissionSet("doc.read_content", "doc.tag")),
		caveat.MaxContentLength(1 << 20),
		caveat.AllowedContentTypes{"image/png", "application/pdf"},
		caveat.MaxBytesTransferred(1 << 30),
		caveat.RequireAuthenticatedRecipient{},
		caveat.RequiredReadiness{"ready", "indexed"},
		caveat.RequireDeclaredDigest{},
		caveat.ClientCIDR(netip.MustParsePrefix("10.0.0.0/8")),
		caveat.DelegationDepth(3),
		caveat.ProcessorAudience("thumbprint-A"),
		caveat.Watermark("renditions/watermarked"),
	}
}

// TestCaveatKindsArePinned fixes every kind string as a literal.
//
// The kinds are inputs to signed bytes: they appear verbatim in a token's
// "cav" claim, so a textual rename across the repository changes what every
// issued token says while every round-trip test still passes. That is
// exactly how a domain tag was rewritten in audit on 2026-10-23 — by a
// find-and-replace over a module path — and the lesson recorded there is
// that a constant entering signed or authenticated bytes needs a test
// asserting its literal, so the failure says "the format changed" instead
// of leaving a reader to work backwards from two values that no longer
// match.
//
// Updating this test to make a build green is the one thing never to do
// with it. A kind change is a wire-format change: it needs a new format
// version and a new committed vector, together.
func TestCaveatKindsArePinned(t *testing.T) {
	t.Parallel()

	want := []string{
		"allowed_content_types",
		"client_cidr",
		"delegation_depth",
		"expires_after_first_use",
		"expires_at",
		"max_bytes_transferred",
		"max_content_length",
		"max_uses",
		"not_before",
		"permission_set",
		"processor_audience",
		"require_authenticated_recipient",
		"require_declared_digest",
		"required_readiness",
		"resource_scope",
		"watermark",
	}
	if got := caveat.RegisteredKinds(); !slices.Equal(got, want) {
		t.Fatalf("RegisteredKinds() = %v,\nwant %v\n"+
			"a caveat kind is an input to signed bytes: changing one changes what every "+
			"issued token says. See docs/wire-format.md.", got, want)
	}

	// And every kind in the vocabulary is actually constructible, so the
	// list above cannot drift from the types.
	kinds := make([]string, 0, 16)
	for _, c := range allKinds(t) {
		kinds = append(kinds, c.Kind())
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, want) {
		t.Fatalf("the constructible kinds are %v, want %v", kinds, want)
	}
}

// TestCodec_DecodeThenEncodeIsByteExact is cas's
// TestPermissionSetCaveat_DecodeThenEncodeNormalizesByteOrder generalised to
// every kind. A caveat that re-encodes differently from how it arrived
// turns two byte sequences into one semantic token, and anything keyed on
// the bytes then has two keys for one credential. cas worked around that
// with Fingerprint; here the codec refuses the non-canonical arrival
// instead, so the problem does not exist to work around.
// TestStandardClaimKindsAreExactlyTheFourWithAClaimCounterpart pins the
// placement rule's membership as literals, for the same reason
// TestCaveatKindsArePinned pins the kind strings: the four are published in
// docs/wire-format.md, and moving a kind into or out of this set changes
// which tokens every conforming verifier accepts.
func TestStandardClaimKindsAreExactlyTheFourWithAClaimCounterpart(t *testing.T) {
	t.Parallel()

	want := []string{"expires_at", "not_before", "permission_set", "resource_scope"}
	got := caveat.StandardClaimKinds()
	if !slices.Equal(got, want) {
		t.Errorf("StandardClaimKinds() = %v, want %v", got, want)
	}
	for _, kind := range want {
		if !caveat.HasStandardClaim(kind) {
			t.Errorf("HasStandardClaim(%q) = false, want true", kind)
		}
	}
	// And no stateful kind is one of them: a stateful caveat is checked
	// against a counter, which no standard claim carries.
	for _, kind := range caveat.StatefulKinds() {
		if caveat.HasStandardClaim(kind) {
			t.Errorf("HasStandardClaim(%q) = true for a stateful kind", kind)
		}
	}
}

func TestCodec_DecodeThenEncodeIsByteExact(t *testing.T) {
	t.Parallel()
	schema := casSchema(t)

	entries, err := caveat.EncodeAll(allKinds(t))
	if err != nil {
		t.Fatalf("EncodeAll() error = %v", err)
	}
	if len(entries) != 16 {
		t.Fatalf("EncodeAll() returned %d entries, want 16", len(entries))
	}

	first, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, err := caveat.DecodeAll(entries, schema)
	if err != nil {
		t.Fatalf("DecodeAll() error = %v", err)
	}
	reencoded, err := caveat.EncodeAll(decoded)
	if err != nil {
		t.Fatalf("EncodeAll(decoded) error = %v", err)
	}
	second, err := json.Marshal(reencoded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if string(first) != string(second) {
		t.Fatalf("decode-then-encode is not byte exact:\nfirst  = %s\nsecond = %s", first, second)
	}
}

// TestCodec_EncodingIsDeterministicRegardlessOfInputOrder pins the property
// the signed bytes depend on: the same set of caveats must always produce
// the same claim, however the caller happened to order them, and whatever
// order a Go map yields.
func TestCodec_EncodingIsDeterministicRegardlessOfInputOrder(t *testing.T) {
	t.Parallel()

	caveats := allKinds(t)
	want, err := caveat.EncodeAll(caveats)
	if err != nil {
		t.Fatalf("EncodeAll() error = %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for shift := range len(caveats) {
		rotated := append(slices.Clone(caveats[shift:]), caveats[:shift]...)
		got, err := caveat.EncodeAll(rotated)
		if err != nil {
			t.Fatalf("EncodeAll(rotated by %d) error = %v", shift, err)
		}
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("rotating the input by %d changed the encoding:\ngot  = %s\nwant = %s", shift, gotJSON, wantJSON)
		}
	}
}

// TestCodec_UnregisteredCaveatKindFailsClosed is cas's test of the same
// name: the registry is the single fail-closed gate every caveat passes
// through when a token is parsed.
func TestCodec_UnregisteredCaveatKindFailsClosed(t *testing.T) {
	t.Parallel()

	if _, err := caveat.DecodeCaveat("never_registered", []byte(`3`), casSchema(t)); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("DecodeCaveat(unregistered) error = %v, want wrapping ErrUnknownCaveat", err)
	}
	if _, err := caveat.Encode(unregisteredKindCaveat{}); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("Encode(unregistered) error = %v, want wrapping ErrUnknownCaveat", err)
	}
}

func TestCodec_RefusesMalformedValues(t *testing.T) {
	t.Parallel()
	schema := casSchema(t)

	cases := []struct {
		name  string
		kind  string
		value string
	}{
		{"a negative use count", "max_uses", `-1`},
		{"a saturating byte limit", "max_bytes_transferred", `9223372036854775807`},
		{"a fractional expiry", "expires_at", `1.5`},
		{"an absurd expiry", "expires_at", `99999999999999`},
		{"a string where a number belongs", "max_content_length", `"1000"`},
		{"an empty processor identity", "processor_audience", `""`},
		{"an empty watermark label", "watermark", `""`},
		{"an unsorted content type list", "allowed_content_types", `["image/png","application/pdf"]`},
		{"a duplicated content type", "allowed_content_types", `["image/png","image/png"]`},
		{"an empty content type list", "allowed_content_types", `[]`},
		{"an empty readiness list", "required_readiness", `[]`},
		{"a presence flag set to false", "require_declared_digest", `false`},
		{"a presence flag set to null", "require_authenticated_recipient", `null`},
		{"an unmasked CIDR", "client_cidr", `"10.0.0.5/8"`},
		{"a malformed CIDR", "client_cidr", `"not-a-prefix"`},
		{"an empty resource scope list", "resource_scope", `[]`},
		{"a resource path with no segments", "resource_scope", `[[]]`},
		{"a resource segment that is not a pair", "resource_scope", `[[["tenant"]]]`},
		{"a resource path the schema refuses", "resource_scope", `[[["bucket","b"]]]`},
		{"an unsorted resource scope list", "resource_scope", `[[["tenant","t2"]],[["tenant","t1"]]]`},
		{"a duplicated resource scope", "resource_scope", `[[["tenant","t1"]],[["tenant","t1"]]]`},
		{"trailing bytes after the value", "max_uses", `3 4`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := caveat.DecodeCaveat(tc.kind, []byte(tc.value), schema); !errors.Is(err, caveat.ErrUnknownCaveat) {
				t.Errorf("DecodeCaveat(%s, %s) error = %v, want wrapping ErrUnknownCaveat", tc.kind, tc.value, err)
			}
		})
	}
}

func TestDecodeAll_RefusesDuplicateAndMisorderedKinds(t *testing.T) {
	t.Parallel()
	schema := casSchema(t)

	dup := []caveat.WireCaveat{
		{Kind: "max_uses", Value: json.RawMessage(`3`)},
		{Kind: "max_uses", Value: json.RawMessage(`1`)},
	}
	if _, err := caveat.DecodeAll(dup, schema); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("DecodeAll(duplicate kinds) error = %v, want wrapping ErrUnknownCaveat", err)
	}

	misordered := []caveat.WireCaveat{
		{Kind: "max_uses", Value: json.RawMessage(`3`)},
		{Kind: "client_cidr", Value: json.RawMessage(`"10.0.0.0/8"`)},
	}
	if _, err := caveat.DecodeAll(misordered, schema); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("DecodeAll(misordered kinds) error = %v, want wrapping ErrUnknownCaveat", err)
	}

	if _, err := caveat.EncodeAll([]caveat.Caveat{caveat.MaxUses(3), caveat.MaxUses(1)}); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("EncodeAll(duplicate kinds) error = %v, want wrapping ErrUnknownCaveat", err)
	}
}

// TestEncodePaths_RefusesAnUnvalidatedPath is the encode-side half of the
// fail-closed guard that makes the decode side's "schema-checked by
// construction" premise true. cas's TestEncodeResource_RefusesUnresolvedRef
// is the same test.
func TestEncodePaths_RefusesAnUnvalidatedPath(t *testing.T) {
	t.Parallel()

	var unvalidated domain.ResourcePath
	scope := caveat.ResourceScope{Scopes: []domain.ResourcePath{unvalidated}}
	if _, err := caveat.Encode(scope); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("Encode(ResourceScope with an unvalidated path) error = %v, want wrapping ErrUnknownCaveat", err)
	}
}

// TestCodec_ErrorsNeverNameTheValue extends the error-discipline canary to
// the codec: a malformed token is the case an attacker iterates on, so a
// decode failure that echoed the value it refused would be the most useful
// oracle in the module.
func TestCodec_ErrorsNeverNameTheValue(t *testing.T) {
	t.Parallel()

	const sentinel = "SENTINEL-value-3c71f"
	_, err := caveat.DecodeCaveat("processor_audience", []byte(`"`+sentinel+`"`+` trailing`), casSchema(t))
	if err == nil {
		t.Fatal("expected DecodeCaveat() to fail")
	}
	if got := err.Error(); contains(got, sentinel) {
		t.Errorf("error %q contains the refused value", got)
	}
	if got := err.Error(); contains(got, "processor_audience") {
		t.Errorf("error %q names the caveat kind", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
