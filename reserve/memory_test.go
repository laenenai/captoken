package reserve

import (
	"context"
	"errors"
	"testing"
)

func TestMemory_ZeroValueIsUsable(t *testing.T) {
	t.Parallel()
	var m Memory
	ctx := context.Background()
	if err := m.Advance(ctx, "chain", Advance{Uses: 1}); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	if err := m.Revoke(ctx, "chain"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := m.Consume(ctx, "chain", "nonce"); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if got := m.Snapshot()["chain"].Uses; got != 1 {
		t.Errorf("Uses = %d, want 1", got)
	}
	revoked, err := m.IsRevoked(ctx, "chain")
	if err != nil || !revoked {
		t.Errorf("IsRevoked() = (%v, %v), want (true, nil)", revoked, err)
	}
	if err := m.Consume(ctx, "chain", "nonce"); !errors.Is(err, ErrNonceConsumed) {
		t.Errorf("Consume(twice) error = %v, want ErrNonceConsumed", err)
	}
}
