# Biscuit probe for `captoken`

Scratch Go module backing
[`../2026-10-23-biscuit-for-captoken.md`](../2026-10-23-biscuit-for-captoken.md).
Every number and verdict in that document comes from a transcript in
`transcripts/`.

Reproduce:

```sh
go test -v .            # Q1, Q2, Q4-Q8: behaviour probes
go test -v ./samples/   # the Rust reference implementation's vectors
govulncheck ./...
```

`samples/` is copied from
`github.com/eclipse-biscuit/biscuit-go/v2@v2.2.2/samples` — the `.bc` files
are test vectors produced by the **Rust** reference implementation, so
running them is the one cross-language check that is possible without a
Rust or Java toolchain. `samples/data/` is byte-identical to upstream, which
is what the cross-language claim rests on; `samples/samples_test.go` is
upstream's harness with two blank lines removed by `gofumpt`, so this
repository's lint step stays clean once it has packages of its own.

| File | Covers |
|---|---|
| `q1_test.go` | Q1: fail-closed stateful caveats, and bearer fact forgery |
| `q2_test.go`, `q2b_test.go` | Q2: caveat expressibility, parser limits, error disclosure |
| `q3_test.go` | Q3: Rust vectors byte-round-tripped through biscuit-go |
| `q4_test.go` | Q4: revocation identifiers; int64 overflow in Datalog |
| `q5_test.go` | Chain truncation, key custody, public-key verification |
| `q6_test.go` | Revocation ids as a single-use key under byte permutation |
| `q7_test.go` | Token size for a realistic caveat set |
| `q8_test.go` | Server-supplied-fact edge cases |
