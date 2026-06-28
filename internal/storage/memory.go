package storage

import (
	"sync"
)

type InMemoryNullifierStore struct {
	mu    sync.RWMutex
	store map[string]bool
}

// NewInMemoryNullifierStore creates a new in-memory nullifier store.
func NewInMemoryNullifierStore() *InMemoryNullifierStore {
	return &InMemoryNullifierStore{
		store: make(map[string]bool),
	}
}

// CheckAndStore checks if a nullifier exists in the store. If it does not exist, it stores the nullifier and returns true. If it already exists, it returns false.
func (s *InMemoryNullifierStore) CheckAndStore(nullifier []byte) (bool, error) {
	key := string(nullifier)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store[key] {
		return false, nil // already exists
	}
	s.store[key] = true
	return true, nil // new
}

// Close is a no-op for the in-memory store, but it implements the NullifierStore interface.
func (s *InMemoryNullifierStore) Close() error {
	return nil
}
