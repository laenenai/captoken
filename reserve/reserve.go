// Package reserve defines the ports the stateful subset of captoken's
// caveats needs, and nothing else.
//
// Three caveats — MaxUses, ExpiresAfterFirstUse and MaxBytesTransferred —
// are not offline-verifiable at all. Each reads a counter that must be read
// inside the operation's own transaction and advanced only once the
// operation has succeeded, which is a database's job and not a token's. The
// charter therefore gives this module a second surface: a verification
// service a third party can get that check done by, rather than
// reimplementing it.
//
// # What this increment contains, and what it deliberately does not
//
// The ports are here, with an in-memory adapter that satisfies them, so the
// chain verifier can be written and tested against the real interfaces. The
// production service — its storage, HTTP transport, request and response
// shapes and authentication — lives in a separate module/repo. This module
// ships only the in-memory test adapter and the fail-closed Stub.
//
// # The ordering discipline, which is the whole reason these are ports
//
// A Counters implementation reads. It never advances. The caller:
//
//  1. opens its transaction;
//  2. reads the counters through Counters.Read;
//  3. calls the verifier, which checks the caveats against that snapshot;
//  4. performs the operation;
//  5. and only if the operation succeeded, persists the advance through
//     Counters.Advance, in the SAME transaction.
//
// Step 5 being inside step 1's transaction and after step 4 is what keeps a
// failed upload from silently consuming a use or a byte allowance. Nothing
// in this module can enforce that ordering — it is a property of the
// caller's transaction — so it is stated here, tested in
// TestStatefulCaveats_DoNotAdvanceWhenTheOperationFails, and exercised by
// the conformance suite against every adapter.
//
// # Revocation keys on the ancestor, not on the token
//
// A chain's revocation identifier is its root link's token id, which every
// descendant carries verbatim in its "cid" claim. Revoking it revokes every
// token ever derived from that root, with no enumeration of descendants and
// no walk of a revocation tree. The Biscuit spike found Biscuit getting
// this for free and recommended this design should too; cas had no
// equivalent, because its Fingerprint hashed the whole token, so revoking a
// parent left its children alive.
package reserve

import (
	"context"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/laenenai/captoken/domain"
)

// ErrNoReservationService is returned when a redemption token is presented
// to a verifier that has no Counters wired up.
//
// It is the fail-closed outcome the charter's two-surface design rests on:
// a verifier that cannot supply the counters refuses rather than skipping
// the check, so ignorance and refusal are the same outcome and the worst
// case of a partial verifier is a refused request, never an accepted one.
var ErrNoReservationService = errors.New("no reservation service")

// ErrRevoked is returned when a chain's revocation identifier is recorded
// as revoked.
var ErrRevoked = errors.New("revoked")

// ErrNonceConsumed is returned when a single-use nonce has already been
// recorded against a chain.
var ErrNonceConsumed = errors.New("nonce already consumed")

// Reservation is the counter snapshot one authorization is evaluated
// against. The zero value is a chain that has never been redeemed.
type Reservation struct {
	// Uses is how many times the chain has already been redeemed.
	Uses int
	// FirstUsedAt is when it was first redeemed, or the zero Time if never.
	FirstUsedAt time.Time
	// BytesTransferred is how many bytes have been served under it — the
	// bytes actually served, never the lengths prior requests declared.
	BytesTransferred int64
}

// Advance is the amount to add to a chain's counters once the operation
// they guarded has succeeded.
type Advance struct {
	// Uses is normally 1.
	Uses int
	// FirstUsedAt is recorded only if the chain has no first-use instant
	// yet; a later Advance never moves it.
	FirstUsedAt time.Time
	// Bytes is the number of bytes actually served.
	Bytes int64
}

// Counters reads and advances the per-chain counters the stateful caveats
// check against. Read never advances; see the package doc comment for the
// ordering the caller owns.
type Counters interface {
	// Read returns the current snapshot for a chain. A chain that has
	// never been redeemed returns the zero Reservation and a nil error:
	// "not found" is not an error here, it is a count of zero.
	Read(ctx context.Context, chain domain.ChainID) (Reservation, error)
	// Advance adds to a chain's counters. The caller calls it only after
	// the guarded operation has succeeded, inside the same transaction.
	Advance(ctx context.Context, chain domain.ChainID, by Advance) error
}

// Revocations answers whether a chain has been revoked. The identifier is
// the chain's root token id, so one record kills every descendant.
type Revocations interface {
	// IsRevoked reports whether id is recorded as revoked.
	IsRevoked(ctx context.Context, id domain.RevocationID) (bool, error)
	// Revoke records id as revoked. Revoking an already-revoked id
	// succeeds: revocation is idempotent and has no undo.
	Revoke(ctx context.Context, id domain.RevocationID) error
}

// Nonces records single-use nonces, for the one-shot operations whose
// at-most-once property cannot be expressed as a counter — a token redeemed
// for an operation that is not retryable.
//
// It is deliberately separate from Counters even though MaxUses(1) looks
// like the same thing. MaxUses counts redemptions of a chain; a nonce
// records that one particular OPERATION has been performed, which a retried
// request must not perform twice even though it is the same redemption.
type Nonces interface {
	// Consume records nonce against chain, returning ErrNonceConsumed if
	// it has been recorded before. It must be atomic: two concurrent calls
	// with the same (chain, nonce) must not both succeed.
	Consume(ctx context.Context, chain domain.ChainID, nonce string) error
}

// Memory is an in-memory Counters, Revocations and Nonces, for tests and
// for a consumer's own unit tests. It is not a production adapter: its
// state is per-process, and the ordering discipline the package doc
// describes needs a real transaction, which this cannot offer.
type Memory struct {
	mu       sync.Mutex
	counters map[domain.ChainID]Reservation
	revoked  map[domain.RevocationID]struct{}
	nonces   map[domain.ChainID]map[string]struct{}
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{
		counters: map[domain.ChainID]Reservation{},
		revoked:  map[domain.RevocationID]struct{}{},
		nonces:   map[domain.ChainID]map[string]struct{}{},
	}
}

// Read implements Counters. The zero Memory is usable.
func (m *Memory) Read(_ context.Context, chain domain.ChainID) (Reservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[chain], nil
}

// Advance implements Counters.
func (m *Memory) Advance(_ context.Context, chain domain.ChainID, by Advance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counters == nil {
		m.counters = map[domain.ChainID]Reservation{}
	}
	cur := m.counters[chain]
	cur.Uses += by.Uses
	cur.BytesTransferred += by.Bytes
	if cur.FirstUsedAt.IsZero() && !by.FirstUsedAt.IsZero() {
		cur.FirstUsedAt = domain.CanonicalTime(by.FirstUsedAt)
	}
	m.counters[chain] = cur
	return nil
}

// IsRevoked implements Revocations.
func (m *Memory) IsRevoked(_ context.Context, id domain.RevocationID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[id]
	return ok, nil
}

// Revoke implements Revocations.
func (m *Memory) Revoke(_ context.Context, id domain.RevocationID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revoked == nil {
		m.revoked = map[domain.RevocationID]struct{}{}
	}
	m.revoked[id] = struct{}{}
	return nil
}

// Consume implements Nonces.
func (m *Memory) Consume(_ context.Context, chain domain.ChainID, nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nonces == nil {
		m.nonces = map[domain.ChainID]map[string]struct{}{}
	}
	seen := m.nonces[chain]
	if seen == nil {
		seen = map[string]struct{}{}
		m.nonces[chain] = seen
	}
	if _, dup := seen[nonce]; dup {
		return ErrNonceConsumed
	}
	seen[nonce] = struct{}{}
	return nil
}

// Snapshot returns a copy of every chain's counters, for assertions in
// tests.
func (m *Memory) Snapshot() map[domain.ChainID]Reservation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.counters)
}

var (
	_ Counters    = (*Memory)(nil)
	_ Revocations = (*Memory)(nil)
	_ Nonces      = (*Memory)(nil)
)

// Stub is the fail-closed placeholder for a missing reservation service. The
// production transport lives in a separate module/repo. Every method refuses
// with ErrNoReservationService.
//
// It exists rather than being omitted so that the fail-closed path has a
// name and a test: a verifier wired to a reservation service that is not
// yet implemented must refuse a redemption token, not accept one. A nil
// Counters and a Stub therefore behave identically, which is the point.
//
// A production adapter in that separate service implements the same port;
// the suite in captokentest is what it has to pass.
type Stub struct{}

// Read implements Counters by refusing.
func (Stub) Read(context.Context, domain.ChainID) (Reservation, error) {
	return Reservation{}, ErrNoReservationService
}

// Advance implements Counters by refusing.
func (Stub) Advance(context.Context, domain.ChainID, Advance) error {
	return ErrNoReservationService
}

var _ Counters = Stub{}
