package chain

import (
	"fmt"
	"log/slog"
)

// Every type in this file holds something a running system must never write to
// a log, a trace or an error string: an Ed25519 private key, or a presentation
// token, which is a bearer credential and therefore material in its own right.
//
// CONVENTIONS.md's "Rendering a secret" convention requires four interfaces
// rather than the one that is usually reached for, and the reason is measured
// rather than reasoned: fmt consults fmt.Stringer for %v, %s, %q, %x and %X and
// for no other verb, so a type carrying only String() prints every byte of its
// material under %d, %c, %o, %b or %U. fmt.Formatter is the only interface fmt
// consults for every verb, which is what makes it load-bearing here; Stringer
// is still needed for the direct String() call and for slog's TextHandler,
// json.Marshaler because encoding/json consults neither of the others, and
// slog.LogValuer because JSONHandler marshals rather than formats.
//
// There is a second reason these methods are defined on four types rather than
// on one key wrapper: fmt cannot call a method on a value it reaches through an
// unexported field, so it abandons the method path for that whole subtree. A
// perfectly redacting key type inside Minter's unexported rootKey would print in
// full. Redaction is not inherited, so every type that transitively holds
// material carries the methods itself.
//
// Two holes are left open deliberately, because no implementation closes them.
// %p and any other bad-verb path reflect the operand without consulting any
// interface — fmt sets its erroring flag first — and a bare ed25519.PrivateKey
// passed around as a value has no type identity of ours to hang a method on.
// SECURITY.md names both.

// redacted writes the type's name and nothing about the value, for every verb.
// The name is kept because a log line naming the type is still diagnosable; the
// length is omitted because knowing a key is 32 bytes rather than 64 removes
// most of a search space.
func redacted(f fmt.State, name string) {
	_, _ = f.Write([]byte(name + "(redacted)"))
}

// String redacts KeyPair, and is what fmt consults for %v, %s, %q, %x and %X and
// what slog's TextHandler reaches through.
func (k KeyPair) String() string { return "captoken.KeyPair(redacted)" }

// Format redacts KeyPair under every verb. It is the load-bearing one: fmt
// consults no other interface for %d, %c, %U, %b or %o, each of which would
// otherwise print the material byte by byte.
func (k KeyPair) Format(f fmt.State, _ rune) { redacted(f, "captoken.KeyPair") }

// MarshalJSON redacts KeyPair, because encoding/json consults neither String nor
// LogValue — and so neither does slog's JSONHandler, which is built on it.
func (k KeyPair) MarshalJSON() ([]byte, error) {
	return []byte(`"captoken.KeyPair(redacted)"`), nil
}

// LogValue redacts KeyPair as a structured log attribute under every handler.
func (k KeyPair) LogValue() slog.Value { return slog.StringValue(k.String()) }

// String redacts Minted, and is what fmt consults for %v, %s, %q, %x and %X and
// what slog's TextHandler reaches through.
func (m Minted) String() string { return "captoken.Minted(redacted)" }

// Format redacts Minted under every verb. It is the load-bearing one: fmt
// consults no other interface for %d, %c, %U, %b or %o, each of which would
// otherwise print the material byte by byte.
func (m Minted) Format(f fmt.State, _ rune) { redacted(f, "captoken.Minted") }

// MarshalJSON redacts Minted, because encoding/json consults neither String nor
// LogValue — and so neither does slog's JSONHandler, which is built on it.
func (m Minted) MarshalJSON() ([]byte, error) {
	return []byte(`"captoken.Minted(redacted)"`), nil
}

// LogValue redacts Minted as a structured log attribute under every handler.
func (m Minted) LogValue() slog.Value { return slog.StringValue(m.String()) }

// String redacts MinterConfig, and is what fmt consults for %v, %s, %q, %x and %X and
// what slog's TextHandler reaches through.
func (c MinterConfig) String() string { return "captoken.MinterConfig(redacted)" }

// Format redacts MinterConfig under every verb. It is the load-bearing one: fmt
// consults no other interface for %d, %c, %U, %b or %o, each of which would
// otherwise print the material byte by byte.
func (c MinterConfig) Format(f fmt.State, _ rune) { redacted(f, "captoken.MinterConfig") }

// MarshalJSON redacts MinterConfig, because encoding/json consults neither String nor
// LogValue — and so neither does slog's JSONHandler, which is built on it.
func (c MinterConfig) MarshalJSON() ([]byte, error) {
	return []byte(`"captoken.MinterConfig(redacted)"`), nil
}

// LogValue redacts MinterConfig as a structured log attribute under every handler.
func (c MinterConfig) LogValue() slog.Value { return slog.StringValue(c.String()) }

// String redacts Minter, and is what fmt consults for %v, %s, %q, %x and %X and
// what slog's TextHandler reaches through.
func (m Minter) String() string { return "captoken.Minter(redacted)" }

// Format redacts Minter under every verb. It is the load-bearing one: fmt
// consults no other interface for %d, %c, %U, %b or %o, each of which would
// otherwise print the material byte by byte.
func (m Minter) Format(f fmt.State, _ rune) { redacted(f, "captoken.Minter") }

// MarshalJSON redacts Minter, because encoding/json consults neither String nor
// LogValue — and so neither does slog's JSONHandler, which is built on it.
func (m Minter) MarshalJSON() ([]byte, error) {
	return []byte(`"captoken.Minter(redacted)"`), nil
}

// LogValue redacts Minter as a structured log attribute under every handler.
func (m Minter) LogValue() slog.Value { return slog.StringValue(m.String()) }
