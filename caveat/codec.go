package caveat

// This file is the caveat layer's wire codec. It replaces cas's
// hand-rolled, length-prefixed binary format outright: a JWT's claims are
// JSON by definition, so a second encoding underneath would be a format a
// third party has to implement twice.
//
// cas's codec.go carried a bounds-checked reader whose readCount heuristic
// (minWireBytesPerElement) existed to stop a handful of input bytes
// claiming billions of elements and forcing an enormous allocation.
// encoding/json owns that now: it allocates as it parses rather than from a
// declared count, so there is no count to bound. What this file still owns,
// because no general codec can, is CANONICALITY — the same caveat must
// always produce the same signed bytes — and that is why every list whose
// order carries no meaning is sorted here and why a non-canonical value
// (an unmasked CIDR, a duplicate list entry) is refused on the way in
// rather than silently normalized on the way out.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/laenenai/captoken/domain"
)

// errMalformedValue is the single cause every decoder reports. Like
// ErrCaveatNotSatisfied it names nothing: DecodeCaveat wraps it into
// ErrUnknownCaveat, and a caller learns that a token was not well formed
// and not which field of it.
var errMalformedValue = errors.New("malformed caveat value")

// MaxListEntries bounds any list a caveat value may carry. A token is a bearer
// credential presented by anyone; the bound keeps the work a hostile one
// can demand before any signature is checked proportional to its size, and
// it is far above any legitimate use (a permission set with more than 256
// members is a design problem, not a token).
const MaxListEntries = 256

// WireCaveat is one entry of a token's "cav" claim: the kind, and the
// kind's own canonical JSON value. The two-field shape rather than a
// single-key object is deliberate — a single-key object makes a decoder
// range a map to find the key it has, and the order a map yields is not
// something a canonical encoding may depend on.
type WireCaveat struct {
	Kind  string          `json:"k"`
	Value json.RawMessage `json:"v"`
}

// Encode returns c's canonical wire entry.
func Encode(c Caveat) (WireCaveat, error) {
	if c == nil {
		return WireCaveat{}, fmt.Errorf("%w: nil caveat", ErrUnknownCaveat)
	}
	enc, ok := c.(encodableCaveat)
	if !ok {
		// A foreign Caveat implementation cannot be put on the wire: its
		// bytes are not part of the published format, so no other verifier
		// could read them. cas refused the same case for the same reason.
		return WireCaveat{}, fmt.Errorf("%w: kind has no canonical encoding", ErrUnknownCaveat)
	}
	if !IsRegisteredKind(enc.Kind()) {
		return WireCaveat{}, fmt.Errorf("%w: unregistered kind", ErrUnknownCaveat)
	}
	value, err := enc.encodeValue()
	if err != nil {
		return WireCaveat{}, fmt.Errorf("%w: value cannot be encoded", ErrUnknownCaveat)
	}
	raw, err := marshalCanonical(value)
	if err != nil {
		return WireCaveat{}, fmt.Errorf("%w: value cannot be encoded", ErrUnknownCaveat)
	}
	return WireCaveat{Kind: enc.Kind(), Value: raw}, nil
}

// EncodeAll returns the canonical "cav" claim for caveats, sorted by kind
// so a given set of caveats always produces the same signed bytes.
//
// It refuses a duplicate kind. Two caveats of one kind on a single link
// would have to be intersected to mean anything, and intersecting them here
// would mean this encoder computing a narrowing — which is exactly the
// comparison Narrows exists to be the single implementation of. The caller
// intersects first, or presents them as separate links.
func EncodeAll(caveats []Caveat) ([]WireCaveat, error) {
	if len(caveats) > MaxListEntries {
		return nil, fmt.Errorf("%w: too many caveats", ErrUnknownCaveat)
	}
	out := make([]WireCaveat, 0, len(caveats))
	seen := make(map[string]struct{}, len(caveats))
	for _, c := range caveats {
		entry, err := Encode(c)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[entry.Kind]; dup {
			return nil, fmt.Errorf("%w: duplicate kind", ErrUnknownCaveat)
		}
		seen[entry.Kind] = struct{}{}
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, b WireCaveat) int {
		switch {
		case a.Kind < b.Kind:
			return -1
		case a.Kind > b.Kind:
			return 1
		default:
			return 0
		}
	})
	return out, nil
}

// DecodeAll reconstructs the caveats in a token's "cav" claim. An
// unregistered kind fails closed, a duplicate kind is refused, and so is a
// claim that is not already in canonical (kind-sorted) order — a token
// whose caveats arrived in some other order would re-encode differently
// from how it arrived, and a chain's links are compared by their decoded
// content rather than their presented bytes, so a non-canonical arrival is
// a difference with nowhere to go.
func DecodeAll(entries []WireCaveat, schema domain.ResourceSchema) ([]Caveat, error) {
	if len(entries) > MaxListEntries {
		return nil, fmt.Errorf("%w: too many caveats", ErrUnknownCaveat)
	}
	out := make([]Caveat, 0, len(entries))
	for i, entry := range entries {
		if i > 0 && entries[i-1].Kind >= entry.Kind {
			return nil, fmt.Errorf("%w: caveats are not in canonical order", ErrUnknownCaveat)
		}
		c, err := DecodeCaveat(entry.Kind, entry.Value, schema)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// EncodePaths returns the canonical wire form of a set of resource paths:
// an array of paths, each an array of two-element [kind, id] arrays. The
// set is sorted and deduplicated so the same scope always produces the same
// bytes.
//
// The nesting is the point. A path stays a SEQUENCE OF SEGMENTS on the
// wire, so a verifier in any language compares it segment by segment. The
// Biscuit spike's finding is what rules out the obvious alternative of one
// joined string: that makes containment a prefix test, and a prefix test
// matched the scope "fs/a" against its sibling "fs/ab".
func EncodePaths(paths []domain.ResourcePath) ([][][]string, error) {
	if len(paths) > MaxListEntries {
		return nil, errMalformedValue
	}
	out := make([][][]string, 0, len(paths))
	for _, p := range paths {
		if !p.Valid() {
			// The fail-closed half of the guard: nothing unvalidated may
			// reach the wire, which is what lets the decoder treat a
			// decoded path as schema-checked by construction. Refusing
			// here keeps the failure attributable to whoever tried to
			// encode it rather than silent.
			return nil, errMalformedValue
		}
		segs := p.Segments()
		wire := make([][]string, len(segs))
		for i, s := range segs {
			wire[i] = []string{s.Kind, s.ID}
		}
		out = append(out, wire)
	}
	slices.SortFunc(out, comparePathWire)
	out = slices.CompactFunc(out, func(a, b [][]string) bool { return comparePathWire(a, b) == 0 })
	return out, nil
}

// DecodePaths reconstructs resource paths from their wire form, validating
// every one against schema.
func DecodePaths(wire [][][]string, schema domain.ResourceSchema) ([]domain.ResourcePath, error) {
	if len(wire) == 0 || len(wire) > MaxListEntries {
		return nil, errMalformedValue
	}
	if !slices.IsSortedFunc(wire, comparePathWire) {
		return nil, errMalformedValue
	}
	out := make([]domain.ResourcePath, 0, len(wire))
	for i, rawPath := range wire {
		if i > 0 && comparePathWire(wire[i-1], rawPath) == 0 {
			return nil, errMalformedValue
		}
		if len(rawPath) == 0 || len(rawPath) > MaxListEntries {
			return nil, errMalformedValue
		}
		segs := make([]domain.Segment, len(rawPath))
		for j, pair := range rawPath {
			if len(pair) != 2 {
				return nil, errMalformedValue
			}
			segs[j] = domain.Segment{Kind: pair[0], ID: pair[1]}
		}
		p, err := schema.Path(segs...)
		if err != nil {
			return nil, errMalformedValue
		}
		out = append(out, p)
	}
	return out, nil
}

// marshalCanonical is the caveat encoder's canonical JSON. It matches the
// chain layer: HTML-sensitive characters stay literal, while Go still
// escapes U+2028 and U+2029.
func marshalCanonical(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// comparePathWire orders two wire paths lexicographically by segment, then
// by kind then id within a segment, then by length. It is the ordering
// EncodePaths sorts by and DecodePaths requires.
func comparePathWire(a, b [][]string) int {
	for i := range min(len(a), len(b)) {
		for j := range min(len(a[i]), len(b[i])) {
			switch {
			case a[i][j] < b[i][j]:
				return -1
			case a[i][j] > b[i][j]:
				return 1
			}
		}
		switch {
		case len(a[i]) < len(b[i]):
			return -1
		case len(a[i]) > len(b[i]):
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// decodeUnixSeconds reads a NumericDate: a JSON integer count of seconds
// since the epoch. A fractional value is refused rather than rounded —
// rounding is a direction, and getting the direction wrong widens a bound
// (see domain.JWTNotBefore).
func decodeUnixSeconds(value []byte) (int64, error) {
	var n int64
	if err := json.Unmarshal(value, &n); err != nil {
		return 0, errMalformedValue
	}
	// Bound the value so a hostile token cannot produce a time.Time whose
	// arithmetic overflows. ±2^40 seconds is roughly ±34,000 years.
	const bound = 1 << 40
	if n < -bound || n > bound {
		return 0, errMalformedValue
	}
	return n, nil
}

// decodeNonNegativeInt reads a JSON integer that must be zero or more. A
// negative bound is refused at decode rather than relied on to fail closed
// at check time: the Biscuit spike found every negative sentinel in cas's
// vocabulary to be a hazard, and the cleanest answer is that the wire form
// has none.
func decodeNonNegativeInt(value []byte) (int64, error) {
	var n int64
	if err := json.Unmarshal(value, &n); err != nil {
		return 0, errMalformedValue
	}
	if n < 0 || n == math.MaxInt64 {
		// MaxInt64 is excluded so that the arithmetic in
		// MaxBytesTransferred.Check and in a caller's own accounting has
		// headroom; a limit that large is indistinguishable from no limit
		// and should be expressed by omitting the caveat.
		return 0, errMalformedValue
	}
	return n, nil
}

// encodeNonNegativeInt is the encoder-side counterpart of
// decodeNonNegativeInt, so a value this package cannot decode is also a value
// it cannot emit.
func encodeNonNegativeInt(n int64) (any, error) {
	if n < 0 || n == math.MaxInt64 {
		return nil, errMalformedValue
	}
	return n, nil
}

// decodeNonEmptyString reads a JSON string that must not be empty.
func decodeNonEmptyString(value []byte) (string, error) {
	var s string
	if err := json.Unmarshal(value, &s); err != nil {
		return "", errMalformedValue
	}
	if s == "" {
		return "", errMalformedValue
	}
	return s, nil
}

// decodeNonEmptyStrings reads a JSON array of non-empty strings in
// canonical order: sorted, with no duplicates. Refusing a non-canonical
// arrival keeps decode-then-encode a byte-exact identity, which is what
// cas's TestPermissionSetCaveat_DecodeThenEncodeNormalizesByteOrder was
// about: a caveat that re-encodes differently from how it arrived makes two
// byte sequences into one semantic token, and anything keyed on the bytes
// then has two keys for one credential.
func decodeNonEmptyStrings(value []byte) ([]string, error) {
	var out []string
	if err := json.Unmarshal(value, &out); err != nil {
		return nil, errMalformedValue
	}
	if len(out) == 0 || len(out) > MaxListEntries {
		return nil, errMalformedValue
	}
	for i, s := range out {
		if s == "" {
			return nil, errMalformedValue
		}
		if i > 0 && out[i-1] >= s {
			return nil, errMalformedValue
		}
	}
	return out, nil
}

// decodePresenceFlag reads the value of a caveat that carries no data. It
// must be exactly JSON true: null, false, 0 and "" are all refused, so a
// presence flag cannot be smuggled in as a value that reads as absent.
func decodePresenceFlag(value []byte) error {
	var b bool
	if err := json.Unmarshal(value, &b); err != nil {
		return errMalformedValue
	}
	if !b {
		return errMalformedValue
	}
	return nil
}

// sortedUnique returns s sorted with duplicates removed, as a new slice.
func sortedUnique[S ~[]E, E ~string](s S) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = string(v)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
