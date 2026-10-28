package caveat

// This file exists for exactly one property, and it is the one that makes
// the whole vocabulary safe to extend: a verifier meeting a caveat kind it
// does not understand must REFUSE, not ignore.
//
// # Why it cannot be a type captokentest declares
//
// The property needs a token that is well formed, correctly signed and
// correctly subsuming in every dimension, and whose only defect is that the
// build reading it does not know one of its caveat kinds. Nothing a consumer
// can call produces one, and that is deliberate rather than an oversight:
//
//   - The facade does not re-export registerCaveat. The vocabulary is
//     closed, and a consumer that could extend it could issue tokens no
//     other verifier understands — which is the interoperability failure
//     the closed vocabulary exists to prevent.
//   - A Caveat implementation declared anywhere else cannot reach the wire
//     even if it is registered, because Encode requires encodableCaveat and
//     encodeValue is an UNEXPORTED method. Only a type declared in this
//     package can satisfy it. That is the encode side of the same closure,
//     and it is why a foreign caveat is refused at mint with
//     ErrUnknownCaveat rather than silently serialized.
//
// So the fixture has to be born here. captokentest registers this kind,
// mints a chain carrying it through the implementation's own Mint and
// Derive, unregisters the kind, and then asks the consumer's verifier to
// verify the chain it already accepted. That is precisely the extensibility
// scenario — an older verifier meeting a token a newer issuer minted — and
// the token is the implementation's own output rather than bytes a test
// assembled, so nothing about the wire layout is assumed.
//
// # Why it is not registered by init, and why unregistering is safe
//
// It registers only while a conformance subtest holds it, so
// RegisteredKinds() is the published sixteen at every other moment and a
// test that asserts the vocabulary's size is unaffected.
//
// Registering and then removing a kind no production token carries cannot
// change the meaning of any other token: no other kind's decoder, value or
// ordering is touched. The one observable effect is on RegisteredKinds()
// itself, for the moment the probe is held, which is why
// RegisterConformanceCaveat hands back the remover rather than leaving the
// caller to find one.
//
// There is deliberately no production path that reaches any of this. Only
// captokentest calls the registration hook below, and the kind string is
// prefixed so that a kind of this name appearing in a real token is
// unmistakably a test fixture that escaped.

import "github.com/laenenai/captoken/domain"

// ConformanceKind is the kind the conformance probe registers under. It is
// not part of the published vocabulary: docs/wire-format.md's table is the
// sixteen, and this is a seventeenth that exists only inside a conformance
// run.
const ConformanceKind = "captokentest.unknown_kind_probe"

// conformanceCaveat is a caveat that is always satisfied, so that a chain
// carrying it verifies while its kind is registered. That control matters as
// much as the refusal it sets up: a subtest asserting only that the chain is
// refused once the kind is gone would pass just as well against a verifier
// that refused the chain for some other reason all along.
type conformanceCaveat struct{}

// Kind implements Caveat.
func (conformanceCaveat) Kind() string { return ConformanceKind }

// Check implements Caveat. It always passes; see the type's doc comment.
func (conformanceCaveat) Check(Request) error { return nil }

// Narrows implements Caveat, as a presence flag does: a child restating it
// narrows, and nothing else does.
func (conformanceCaveat) Narrows(parent Caveat) bool {
	_, ok := parent.(conformanceCaveat)
	return ok
}

func (conformanceCaveat) encodeValue() (any, error) { return true, nil }

func decodeConformanceCaveat(value []byte, _ domain.ResourceSchema) (Caveat, error) {
	if err := decodePresenceFlag(value); err != nil {
		return nil, err
	}
	return conformanceCaveat{}, nil
}

// RegisterConformanceCaveat registers the probe kind and returns the caveat
// to put on the wire plus the function that removes it again. The caller must
// call that function — with t.Cleanup, which is what captokentest does —
// because the registry is process-global and a kind left registered would
// change what RegisteredKinds() reports for every later test in the same
// binary. It is a test hook, not an extension point; production code must not
// call it.
func RegisterConformanceCaveat() (Caveat, func()) {
	registerCaveat(ConformanceKind, decodeConformanceCaveat)
	return conformanceCaveat{}, func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		delete(registry, ConformanceKind)
	}
}
