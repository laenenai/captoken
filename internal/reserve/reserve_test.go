package reserve_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/laenenai/captoken/internal/domain"
	"github.com/laenenai/captoken/internal/reserve"
)

const chainA = domain.ChainID("chain-a")

// TestMemory_ReadIsZeroForAChainNeverRedeemed pins the contract's one
// surprising edge: "not found" is not an error here, it is a count of zero.
// An adapter that returned a not-found error would make every first use of
// every token fail.
func TestMemory_ReadIsZeroForAChainNeverRedeemed(t *testing.T) {
	t.Parallel()

	got, err := reserve.NewMemory().Read(t.Context(), chainA)
	if err != nil {
		t.Fatalf("Read() error = %v, want nil", err)
	}
	if got != (reserve.Reservation{}) {
		t.Errorf("Read() = %+v, want the zero Reservation", got)
	}
}

// TestMemory_AdvanceAccumulatesAndPinsFirstUse checks the one piece of
// logic an Advance has: a later Advance never moves an existing first-use
// instant, because the window ExpiresAfterFirstUse measures starts at the
// FIRST redemption and a token that moved it forward on every use would
// never expire.
func TestMemory_AdvanceAccumulatesAndPinsFirstUse(t *testing.T) {
	t.Parallel()

	m := reserve.NewMemory()
	first := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	if err := m.Advance(t.Context(), chainA, reserve.Advance{Uses: 1, Bytes: 100, FirstUsedAt: first}); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}
	if err := m.Advance(t.Context(), chainA, reserve.Advance{
		Uses: 1, Bytes: 50, FirstUsedAt: first.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Advance() error = %v", err)
	}

	got, err := m.Read(t.Context(), chainA)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got.Uses != 2 || got.BytesTransferred != 150 {
		t.Errorf("Read() = %+v, want 2 uses and 150 bytes", got)
	}
	if !got.FirstUsedAt.Equal(first) {
		t.Errorf("FirstUsedAt = %v, want %v: a later Advance must not move it", got.FirstUsedAt, first)
	}
	if got.FirstUsedAt != domain.CanonicalTime(got.FirstUsedAt) {
		t.Errorf("FirstUsedAt = %v is not canonical; an instant that is stored and compared must be",
			got.FirstUsedAt)
	}
}

// TestMemory_NonceIsConsumedOnceEvenUnderConcurrency is the at-most-once
// property, and the reason Nonces is a port rather than a counter: exactly
// one of N concurrent attempts at the same operation may succeed.
func TestMemory_NonceIsConsumedOnceEvenUnderConcurrency(t *testing.T) {
	t.Parallel()

	m := reserve.NewMemory()
	const attempts = 32

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.Consume(t.Context(), chainA, "operation-1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case !errors.Is(err, reserve.ErrNonceConsumed):
				t.Errorf("Consume() error = %v, want nil or ErrNonceConsumed", err)
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent attempts at one operation succeeded, want exactly 1", succeeded, attempts)
	}
	// A different operation under the same chain is a different record.
	if err := m.Consume(t.Context(), chainA, "operation-2"); err != nil {
		t.Errorf("Consume(a different nonce) error = %v, want nil", err)
	}
}

func TestMemory_RevocationIsIdempotentAndHasNoUndo(t *testing.T) {
	t.Parallel()

	m := reserve.NewMemory()
	if revoked, err := m.IsRevoked(t.Context(), chainA); err != nil || revoked {
		t.Fatalf("IsRevoked() = (%v, %v), want (false, nil)", revoked, err)
	}
	for range 3 {
		if err := m.Revoke(t.Context(), chainA); err != nil {
			t.Fatalf("Revoke() error = %v, want nil (revocation is idempotent)", err)
		}
	}
	if revoked, err := m.IsRevoked(t.Context(), chainA); err != nil || !revoked {
		t.Fatalf("IsRevoked() after Revoke = (%v, %v), want (true, nil)", revoked, err)
	}
}

// TestStub_RefusesEverything is the fail-closed path the charter's
// two-surface design needs, given a name and a test. A verifier wired to a
// reservation service that does not exist yet must refuse a redemption
// token, not accept one — so a nil Counters and this Stub behave
// identically, which is the point of it existing rather than being omitted.
func TestStub_RefusesEverything(t *testing.T) {
	t.Parallel()

	var stub reserve.Stub
	if _, err := stub.Read(t.Context(), chainA); !errors.Is(err, reserve.ErrNoReservationService) {
		t.Errorf("Stub.Read() error = %v, want wrapping ErrNoReservationService", err)
	}
	if err := stub.Advance(t.Context(), chainA, reserve.Advance{Uses: 1}); !errors.Is(err, reserve.ErrNoReservationService) {
		t.Errorf("Stub.Advance() error = %v, want wrapping ErrNoReservationService", err)
	}
}
