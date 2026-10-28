package caveat

import (
	"testing"

	"github.com/laenenai/captoken/domain"
)

func FuzzDecodeCaveat(f *testing.F) {
	f.Add("max_uses", []byte(`1`))
	f.Add("expires_at", []byte(`0`))
	f.Add("allowed_content_types", []byte(`[]`))
	f.Fuzz(func(_ *testing.T, kind string, value []byte) {
		_, _ = DecodeCaveat(kind, value, domain.ResourceSchema{})
	})
}
