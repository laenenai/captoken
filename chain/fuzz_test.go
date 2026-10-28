package chain

import "testing"

func FuzzSplitPresentation(f *testing.F) {
	f.Add(Prefix + Separator + "header.payload.signature")
	f.Add("not-a-presentation")
	f.Fuzz(func(_ *testing.T, presented string) {
		_, _ = splitPresentation(presented, DefaultMaxLinks)
	})
}

func FuzzParseClaims(f *testing.F) {
	f.Add("header." + "eyJjdHYiOjF9" + ".signature")
	f.Add("...")
	f.Fuzz(func(_ *testing.T, compact string) {
		_, _ = parseClaims(compact)
	})
}

func FuzzDecodeJWK(f *testing.F) {
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = decodeJWK(raw)
	})
}
