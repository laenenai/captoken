package caveat

import (
	"errors"
	"testing"

	"github.com/laenenai/captoken/domain"
)

// TestDecodeCaveat_RejectsNilResultFromDecoder is cas's regression test for
// a registered decoder returning (nil, nil): a nil Caveat in a grant panics
// the moment anything calls Kind() on it, because there is no concrete type
// to dispatch to. It lives in the package so registration can stay
// unexported.
func TestDecodeCaveat_RejectsNilResultFromDecoder(t *testing.T) {
	const kind = "test.returns_nil"
	registerCaveat(kind, func([]byte, domain.ResourceSchema) (Caveat, error) {
		return nil, nil //nolint:nilnil // the point of the test
	})
	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		delete(registry, kind)
	})

	if _, err := DecodeCaveat(kind, []byte(`null`), domain.ResourceSchema{}); !errors.Is(err, ErrUnknownCaveat) {
		t.Errorf("DecodeCaveat() with a decoder returning nil error = %v, want wrapping ErrUnknownCaveat", err)
	}
}
