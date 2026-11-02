// SPDX-License-Identifier: Apache-2.0

package users

import "sync"

const (
	BootstrapIssued  = "issued"
	BootstrapRetired = "retired"
)

// BootstrapEvent is delivered only after a credential transaction commits.
// Password is set only for issued events and is for private delivery, never
// logging or persistence. The users store does not retain the plaintext.
type BootstrapEvent struct {
	Kind       string `json:"kind"`
	Username   string `json:"username"`
	UserID     string `json:"userId"`
	Generation int64  `json:"generation"`
	Reason     string `json:"reason"`
	Password   string `json:"-"`
}

// BootstrapMetadata is the complete secret-free payload accepted by the audit
// ledger. Construct it explicitly from an issued event; do not append events.
type BootstrapMetadata struct {
	Username   string `json:"username"`
	Generation int64  `json:"generation"`
	Reason     string `json:"reason"`
}

// BootstrapLedger queues issuance metadata until the caller can audit it.
// Its zero value is ready to use. Do not copy a ledger after first use.
type BootstrapLedger struct {
	mu      sync.Mutex
	pending []BootstrapMetadata
}

func (l *BootstrapLedger) Append(metadata BootstrapMetadata) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = append(l.pending, metadata)
}

// Drain atomically transfers all pending records to the caller in append order.
// Boot drains after EnsureDefaultAdmin; factory reset drains after its audit
// wipe. A second drain without an append returns nil.
func (l *BootstrapLedger) Drain() []BootstrapMetadata {
	l.mu.Lock()
	defer l.mu.Unlock()
	pending := l.pending
	l.pending = nil
	return pending
}

type bootstrapObserver struct {
	mu sync.Mutex
	fn func(BootstrapEvent)
}

// SetBootstrapObserver replaces this store's observer. Nil disables it. The
// callback runs synchronously outside the observer mutex and may call the store.
// Register before bootstrap and keep registered through shutdown.
func (s *SQLiteStore) SetBootstrapObserver(fn func(BootstrapEvent)) {
	s.bootstrapObserver.mu.Lock()
	defer s.bootstrapObserver.mu.Unlock()
	s.bootstrapObserver.fn = fn
}

// emitBootstrapEvents must be called by mutation paths only after commit,
// outside any store/transaction lock. It performs no issuance or logging.
func (s *SQLiteStore) emitBootstrapEvents(events []BootstrapEvent) {
	s.bootstrapObserver.mu.Lock()
	fn := s.bootstrapObserver.fn
	s.bootstrapObserver.mu.Unlock()
	if fn != nil {
		for _, event := range events {
			fn(event)
		}
	}
}
