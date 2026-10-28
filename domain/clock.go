package domain

import "time"

// Clock abstracts the current time so minting and verification can be
// driven deterministically in tests. It is declared here rather than taken
// from a shared module on purpose: returning the current time is not a
// thing you get subtly wrong, so the ceremony of a module would exceed the
// content, and Go's structural typing makes this interface interchangeable
// with the identically shaped one every sibling module declares. See
// CONVENTIONS.md, "When something deserves its own module".
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock, backed by the real wall clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

var _ Clock = SystemClock{}

// FixedClock is a test Clock that returns a fixed instant until advanced.
// It is not safe for concurrent use.
type FixedClock struct {
	now time.Time
}

// NewFixedClock returns a FixedClock starting at t.
func NewFixedClock(t time.Time) *FixedClock { return &FixedClock{now: t} }

// Now returns the clock's current fixed instant.
func (c *FixedClock) Now() time.Time { return c.now }

// Advance moves the clock's fixed instant forward by d.
func (c *FixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

var _ Clock = (*FixedClock)(nil)

// CanonicalTime normalizes t to UTC at microsecond precision. It is the
// same three lines, with the same test, as audit's domain.CanonicalTime,
// copied rather than shared per CONVENTIONS.md: truncate versus round, and
// the order of UTC conversion versus truncation, both change the result, so
// it is logic that can be wrong and must not be reinvented per module.
//
// Everything in this module that compares or stores an instant goes through
// it. Truncate also strips any monotonic reading, which keeps a time.Now()
// value and its serialized form comparing equal.
func CanonicalTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

// JWTNotAfter and JWTNotBefore normalize an instant for a JWT NumericDate
// claim, which RFC 7519 defines as a count of whole SECONDS. A bound
// carried as exp or nbf therefore loses sub-second precision the moment it
// is signed, and the direction that precision is lost in is a security
// property rather than a rounding preference: each must move the bound
// inwards, never outwards, so that a round trip through the wire can only
// ever narrow what a token permits.
//
// JWTNotAfter floors, bringing an expiry at most a second earlier.
func JWTNotAfter(t time.Time) time.Time {
	return t.UTC().Truncate(time.Second)
}

// JWTNotBefore ceils, pushing a start instant at most a second later. The
// asymmetry with JWTNotAfter is the point: flooring both would push nbf
// earlier, which widens the validity window, and a widening that is "only
// a second" is still a widening this module's central invariant forbids.
func JWTNotBefore(t time.Time) time.Time {
	floored := t.UTC().Truncate(time.Second)
	if floored.Equal(t.UTC()) {
		return floored
	}
	return floored.Add(time.Second)
}
