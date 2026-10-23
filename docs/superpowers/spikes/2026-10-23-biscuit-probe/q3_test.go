package biscuitprobe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	biscuit "github.com/eclipse-biscuit/biscuit-go/v2"
)

// Q3 cross-language, the part that CAN be run here: the .bc vectors in
// samples/data/current are produced by the Rust reference implementation
// (biscuit-rust). Unmarshal each with biscuit-go and re-Serialize it; if
// the bytes come back identical, biscuit-go's writer is byte-compatible
// with the reader Rust produced them for.
func TestQ3_RustVectorsByteRoundTrip(t *testing.T) {
	files, err := filepath.Glob("samples/data/current/*.bc")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sample vectors found: %v", err)
	}
	sort.Strings(files)
	var identical, differing, unparseable []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b, err := biscuit.Unmarshal(raw)
		if err != nil {
			unparseable = append(unparseable, fmt.Sprintf("%s (%v)", filepath.Base(f), err))
			continue
		}
		out, err := b.Serialize()
		if err != nil {
			unparseable = append(unparseable, fmt.Sprintf("%s (serialize: %v)", filepath.Base(f), err))
			continue
		}
		if bytes.Equal(raw, out) {
			identical = append(identical, filepath.Base(f))
		} else {
			differing = append(differing, fmt.Sprintf("%s (in %dB, out %dB)", filepath.Base(f), len(raw), len(out)))
		}
	}
	fmt.Printf("\n### Rust-generated vectors through biscuit-go (%d files)\n", len(files))
	fmt.Printf("  byte-identical re-serialization: %d\n", len(identical))
	fmt.Printf("  parsed but re-serialized differently: %d\n", len(differing))
	for _, d := range differing {
		fmt.Printf("      %s\n", d)
	}
	fmt.Printf("  NOT PARSEABLE by biscuit-go: %d\n", len(unparseable))
	for _, u := range unparseable {
		fmt.Printf("      %s\n", u)
	}
	fmt.Printf("  biscuit-go MaxSchemaVersion = %d\n", biscuit.MaxSchemaVersion)
}
