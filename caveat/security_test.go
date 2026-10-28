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

func TestDecodeCaveat_RejectsNonCanonicalValues(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"max_uses":           []byte(`-0`),
		"max_content_length": []byte(`null`),
		"client_cidr":        []byte(`"10.0.0.0\/8"`),
		"watermark":          []byte(`"\u0061"`),
	}
	for kind, value := range cases {
		t.Run(kind, func(t *testing.T) {
			if _, err := caveat.DecodeCaveat(kind, value, domain.ResourceSchema{}); !errors.Is(err, caveat.ErrUnknownCaveat) {
				t.Errorf("DecodeCaveat(%s, %s) error = %v, want wrapping ErrUnknownCaveat", kind, value, err)
			}
		})
	}
}
