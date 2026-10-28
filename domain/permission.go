package domain

import (
	"fmt"
	"slices"
	"unicode/utf8"
)

// ErrMalformedPermission is returned by ParsePermission when s cannot be a
// permission at all: empty, or not valid UTF-8.
//
// There is deliberately no closed set of permission strings here, unlike
// cas's domain.Permission. The charter forbids this module from knowing a
// consumer's policy vocabulary: a permission is an opaque label this module
// compares for equality and nothing else. Which labels exist, and what they
// mean, is the consumer's business.
var ErrMalformedPermission = newSentinel("malformed permission")

// Permission is one opaque capability label a token grants. This module
// never interprets one; it compares them for equality and computes set
// containment over them.
type Permission string

// ParsePermission validates s as a permission label.
func ParsePermission(s string) (Permission, error) {
	if s == "" {
		return "", fmt.Errorf("%w: empty", ErrMalformedPermission)
	}
	if len(s) > MaxIDLength {
		return "", fmt.Errorf("%w: too long", ErrMalformedPermission)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: not valid UTF-8", ErrMalformedPermission)
	}
	return Permission(s), nil
}

// PermissionSet is a set of permission labels. Carried over from cas's
// domain.PermissionSet unchanged apart from the permission type's own
// loosening above, because set containment is the one operation the
// subsumption rule needs and this is the shape that was already proven.
type PermissionSet map[Permission]struct{}

// NewPermissionSet returns the set containing perms.
func NewPermissionSet(perms ...Permission) PermissionSet {
	s := make(PermissionSet, len(perms))
	for _, p := range perms {
		s[p] = struct{}{}
	}
	return s
}

// Contains reports whether p is a member of s.
func (s PermissionSet) Contains(p Permission) bool {
	_, ok := s[p]
	return ok
}

// IsSubsetOf reports whether every permission in s is also in other. A set
// is a subset of itself.
func (s PermissionSet) IsSubsetOf(other PermissionSet) bool {
	for p := range s {
		if !other.Contains(p) {
			return false
		}
	}
	return true
}

// Intersect returns the permissions present in both s and other.
func (s PermissionSet) Intersect(other PermissionSet) PermissionSet {
	out := make(PermissionSet)
	for p := range s {
		if other.Contains(p) {
			out[p] = struct{}{}
		}
	}
	return out
}

// Sorted returns the set's members in lexicographic order. Everything that
// encodes a PermissionSet into a token's claims goes through this rather
// than ranging the map, since Go map iteration order is randomized and the
// claims are signed bytes that must be reproducible.
func (s PermissionSet) Sorted() []Permission {
	out := make([]Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}
