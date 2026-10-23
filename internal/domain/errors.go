// Package domain holds captoken's value objects: the resource schema a
// consumer declares, the opaque permission and subject identifiers a token
// carries, and the clock and canonical-time helpers everything that digests
// or compares an instant goes through.
//
// Two invariants live here rather than in the layers above, because they
// are properties of the values themselves:
//
//   - A ResourcePath cannot exist without having passed the schema that
//     declares its shape, and containment over one is a segment-wise
//     comparison, never a string prefix.
//   - No error produced here names a value it was given. Every sentinel is
//     a bare cause; a verifier that explains which value failed hands an
//     attacker a dimension to search along.
package domain

import "errors"

// newSentinel declares a sentinel error. It exists so that every sentinel
// in this package is created the same way and so that the package's errors
// are, by inspection, a closed set of bare causes with no formatted values
// in them.
func newSentinel(text string) error { return errors.New(text) }
