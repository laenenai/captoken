package caveat_test

import (
	"errors"
	"testing"

	"github.com/laenenai/captoken/caveat"
	"github.com/laenenai/captoken/domain"
)

func TestDecodeCaveat_RejectsOverflowingFirstUseWindow(t *testing.T) {
	t.Parallel()
	if _, err := caveat.DecodeCaveat("expires_after_first_use", []byte("9223372037"), domain.ResourceSchema{}); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("DecodeCaveat(overflowing duration) error = %v, want wrapping ErrUnknownCaveat", err)
	}
}

func TestDecodeCaveat_RejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	if _, err := caveat.DecodeCaveat("watermark", []byte("\"\xff\""), domain.ResourceSchema{}); !errors.Is(err, caveat.ErrUnknownCaveat) {
		t.Errorf("DecodeCaveat(invalid UTF-8) error = %v, want wrapping ErrUnknownCaveat", err)
	}
}
