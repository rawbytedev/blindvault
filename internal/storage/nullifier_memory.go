package storage

import (
	"context"
	"sync"
)

type InMemoryNullifierStore struct {
	mu    sync.RWMutex
	store map[string]bool
}

// NewInMemoryNullifierStore creates a new in-memory nullifier store.
func NewInMemoryNullifierStore() NullifierStore {
	return &InMemoryNullifierStore{
		store: make(map[string]bool),
	}
}

// CheckAndStore checks if a nullifier exists in the store. If it does not exist, it stores the nullifier and returns true. If it already exists, it returns false.
func (s *InMemoryNullifierStore) CheckAndStore(ctx context.Context, nullifier []byte) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	key := string(nullifier)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store[key] {
		return false, nil // already exists
	}
	s.store[key] = true
	return true, nil // new
}

func (s *InMemoryNullifierStore) Ping(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Close is a no-op for the in-memory store, but it implements the NullifierStore interface.
func (s *InMemoryNullifierStore) Close() error {
	return nil
}
