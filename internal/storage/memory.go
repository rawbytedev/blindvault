package storage

import (
	"sync"
)

type InMemoryNullifierStore struct {
	mu    sync.RWMutex
	store map[string]bool
}

func NewInMemoryNullifierStore() *InMemoryNullifierStore {
	return &InMemoryNullifierStore{
		store: make(map[string]bool),
	}
}

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

func (s *InMemoryNullifierStore) Close() error {
	return nil
}
