package biscuitprobe

import (
	"fmt"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

// Parser limits found while modelling the bespoke caveat set.
func TestQ2_ParserLimits(t *testing.T) {
	fmt.Println("\n### Datalog parser limits (biscuit-go v2.2.2)")
	for _, s := range []string{
		`content_length(-1);`,
		`content_length(0 - 1);`,
		`check if content_length($n), $n >= 0, $n <= 1048576;`,
		`bytes_before(9223372036854775807);`,
		`check if bytes_before($b), content_length($c), $b + $c <= 100;`,
		`check if uses($u), $u < 1;`,
		`slot_index(-1);`,
	} {
		_, err := parser.FromStringAuthorizer(s)
		if err != nil {
			fmt.Printf("  %-60s PARSE ERROR: %v\n", s, err)
		} else {
			fmt.Printf("  %-60s parsed OK\n", s)
		}
	}
}

// Does the authorization error leak which check failed and its contents?
func TestQ2_ErrorMessageIsAnOracle(t *testing.T) {
	fmt.Println("\n### Error-message disclosure")
	raw, pub := mint(t, `
		check if processor($p), $p == "sha256:SECRET-THUMBPRINT-aabbccddeeff";
		check if client_in_cidr("10.16.0.0/12");
	`)
	err := authorize(t, raw, pub, `processor("sha256:attacker"); allow if true;`)
	fmt.Printf("  Authorize() error verbatim:\n    %v\n", err)
}
