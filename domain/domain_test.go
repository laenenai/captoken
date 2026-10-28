package domain_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/laenenai/captoken/domain"
)

func TestPermissionSet_ContainmentAndSubset(t *testing.T) {
	t.Parallel()

	read := domain.Permission("doc.read")
	write := domain.Permission("doc.write")
	del := domain.Permission("doc.delete")

	parent := domain.NewPermissionSet(read, write)
	child := domain.NewPermissionSet(read)
	wider := domain.NewPermissionSet(read, write, del)

	if !child.IsSubsetOf(parent) {
		t.Error("a subset must report IsSubsetOf")
	}
	if wider.IsSubsetOf(parent) {
		t.Error("a superset must not report IsSubsetOf")
	}
	if !parent.IsSubsetOf(parent) {
		t.Error("a set must be a subset of itself")
	}
	if !parent.Contains(read) || parent.Contains(del) {
		t.Error("Contains disagrees with the set's membership")
	}
	if got := parent.Intersect(wider).Sorted(); !slices.Equal(got, []domain.Permission{read, write}) {
		t.Errorf("Intersect().Sorted() = %v, want [doc.read doc.write]", got)
	}
}

// TestPermissionSet_SortedIsDeterministic matters because a permission set
// is encoded into signed bytes. Go map iteration order is randomized, so an
// encoder that ranged the map would produce a different token on every call
// for the same grant.
func TestPermissionSet_SortedIsDeterministic(t *testing.T) {
	t.Parallel()

	s := domain.NewPermissionSet("c", "a", "b", "aa")
	want := []domain.Permission{"a", "aa", "b", "c"}
	for range 32 {
		if got := s.Sorted(); !slices.Equal(got, want) {
			t.Fatalf("Sorted() = %v, want %v", got, want)
		}
	}
}

func TestParsePermission_RefusesWhatCannotBeALabel(t *testing.T) {
	t.Parallel()

	if _, err := domain.ParsePermission(""); !errors.Is(err, domain.ErrMalformedPermission) {
		t.Errorf("ParsePermission(\"\") error = %v, want wrapping ErrMalformedPermission", err)
	}
	if _, err := domain.ParsePermission("\xff"); !errors.Is(err, domain.ErrMalformedPermission) {
		t.Errorf("ParsePermission(invalid utf-8) error = %v, want wrapping ErrMalformedPermission", err)
	}
	if got, err := domain.ParsePermission("doc.read"); err != nil || got != "doc.read" {
		t.Errorf("ParsePermission(\"doc.read\") = (%q, %v), want (\"doc.read\", nil)", got, err)
	}
}

func TestParseID_RefusesWhatCannotBeAnID(t *testing.T) {
	t.Parallel()

	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	cases := map[string]string{"empty": "", "too long": string(long), "invalid utf-8": "\xff"}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseID("subject", in); !errors.Is(err, domain.ErrMalformedID) {
				t.Errorf("ParseID() error = %v, want wrapping ErrMalformedID", err)
			}
		})
	}
}

// TestNewTokenID_IsUnguessableAndUnique pins the property RevocationID's doc
// comment depends on: a chain's root id is its revocation key, so a
// predictable id would let anyone who can enumerate revoke other chains.
func TestNewTokenID_IsUnguessableAndUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[domain.TokenID]struct{}, 1000)
	for range 1000 {
		id, err := domain.NewTokenID()
		if err != nil {
			t.Fatalf("NewTokenID() error = %v", err)
		}
		if len(id) != 22 {
			t.Fatalf("NewTokenID() = %q, want 22 base64url characters (128 bits)", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("NewTokenID() returned %q twice in 1000 draws", id)
		}
		seen[id] = struct{}{}
	}
}

// TestCanonicalTimeIsRoundTrippableThroughMicrosecondStorage is audit's
// test, copied with the function, per CONVENTIONS.md: the same three lines
// with the same test in every module that digests, keys or compares an
// instant.
func TestCanonicalTimeIsRoundTrippableThroughMicrosecondStorage(t *testing.T) {
	t.Parallel()

	for _, in := range []time.Time{
		time.Now(),
		time.Date(2026, 10, 23, 1, 2, 3, 123456789, time.UTC),
		time.Date(2026, 10, 23, 1, 2, 3, 999999999, time.FixedZone("x", 3600)),
	} {
		got := domain.CanonicalTime(in)
		if got.Nanosecond()%1000 != 0 {
			t.Fatalf("CanonicalTime(%v).Nanosecond() = %d, want a whole number of microseconds", in, got.Nanosecond())
		}
		if got.Location() != time.UTC {
			t.Fatalf("CanonicalTime(%v) is in %v, want UTC", in, got.Location())
		}
		if again := domain.CanonicalTime(got); !again.Equal(got) {
			t.Fatalf("CanonicalTime is not idempotent: %v then %v", got, again)
		}
	}
}

// TestJWTTimeMovesEveryBoundInwards is the asymmetry test. RFC 7519's
// NumericDate is whole seconds, so sub-second precision is lost when a
// bound is signed; losing it outwards would widen the validity window,
// which the module's central invariant forbids however small the amount.
func TestJWTTimeMovesEveryBoundInwards(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	frac := base.Add(500 * time.Millisecond)

	if got := domain.JWTNotAfter(frac); !got.Equal(base) {
		t.Errorf("JWTNotAfter(%v) = %v, want %v (an expiry may only move earlier)", frac, got, base)
	}
	if got := domain.JWTNotBefore(frac); !got.Equal(base.Add(time.Second)) {
		t.Errorf("JWTNotBefore(%v) = %v, want %v (a start may only move later)", frac, got, base.Add(time.Second))
	}

	// A bound already on a whole second is left exactly where it is, in
	// both directions, so a canonical value is a fixed point.
	if got := domain.JWTNotAfter(base); !got.Equal(base) {
		t.Errorf("JWTNotAfter is not idempotent on a whole second: %v", got)
	}
	if got := domain.JWTNotBefore(base); !got.Equal(base) {
		t.Errorf("JWTNotBefore is not idempotent on a whole second: %v", got)
	}
}

func TestFixedClockAdvances(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	c := domain.NewFixedClock(start)
	if !c.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", c.Now(), start)
	}
	c.Advance(90 * time.Second)
	if want := start.Add(90 * time.Second); !c.Now().Equal(want) {
		t.Fatalf("after Advance, Now() = %v, want %v", c.Now(), want)
	}
}
