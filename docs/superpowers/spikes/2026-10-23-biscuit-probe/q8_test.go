package biscuitprobe

import (
	"fmt"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

// Edge cases in the server-supplied-fact model that captoken would have to
// design around.
func TestQ8_ServerFactEdgeCases(t *testing.T) {
	chk := `check if uses_remaining($n), $n > 0;`

	fmt.Println("\n### Type confusion: the fact arrives with the wrong term type")
	run(t, "uses_remaining(3) -- integer, correct", chk, `uses_remaining(3); allow if true;`)
	run(t, `uses_remaining("unlimited") -- string`, chk, `uses_remaining("unlimited"); allow if true;`)
	run(t, "uses_remaining(true) -- bool", chk, `uses_remaining(true); allow if true;`)
	run(t, "uses_remaining() -- wrong arity (0)", chk, `uses_remaining(); allow if true;`)
	run(t, "uses_remaining(0, 5) -- wrong arity (2)", chk, `uses_remaining(0, 5); allow if true;`)

	fmt.Println("\n### Existential semantics: MULTIPLE facts for the same predicate")
	fmt.Println("    Datalog checks are existential -- ANY matching fact satisfies them.")
	run(t, "uses_remaining(0) AND uses_remaining(5) both injected", chk,
		`uses_remaining(0); uses_remaining(5); allow if true;`)
	fmt.Println("    ^ if that is AUTHORIZED, a stale counter alongside the true one FAILS OPEN")

	fmt.Println("\n### Negation: can a check demand the ABSENCE of a fact?")
	for _, code := range []string{
		`check if !revoked();`,
		`check if not revoked();`,
		`reject if revoked();`,
	} {
		runParse(code)
	}

	fmt.Println("\n### Clock skew: Biscuit has no notion of tolerance")
	fmt.Println("    the bespoke code applies +/-60s symmetrically in every time caveat;")
	fmt.Println("    in Biscuit the tolerance must be baked into either the bound at mint")
	fmt.Println("    time or the time() fact at authorize time. Demonstrating the latter:")
	ex := `check if time($t), $t <= 2026-10-23T12:00:00Z;`
	run(t, "now = expiry + 30s, no tolerance applied", ex, `time(2026-10-23T12:00:30Z); allow if true;`)
	run(t, "now = expiry + 30s, authorizer subtracts 60s tolerance", ex, `time(2026-10-23T11:59:30Z); allow if true;`)
}

func runParse(code string) {
	_, err := parseAuthorizerOrBlock(code)
	if err != nil {
		fmt.Printf("  %-50s PARSE ERROR: %v\n", code, err)
	} else {
		fmt.Printf("  %-50s parsed OK\n", code)
	}
}

func parseAuthorizerOrBlock(code string) (any, error) {
	return parser.FromStringBlock(code)
}
