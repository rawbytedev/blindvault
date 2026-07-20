package storage

import (
	"sync"
	"time"
)

type InMemoryRevocationStore struct {
	mu    sync.RWMutex
	store map[string]RevocationEntry
}

// NewInMemoryRevocationStore creates a new in-memory revocation store.
func NewInMemoryRevocationStore() RevocationStore {
	return &InMemoryRevocationStore{
		store: make(map[string]RevocationEntry),
	}
}

func (s *InMemoryRevocationStore) RevokeClass(class, epoch, reason, revokedBy string, revokedUntil *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.revocationKey(class, epoch)
	s.store[key] = RevocationEntry{
		CredentialClass: class,
		KeyEpoch:        epoch,
		Reason:          reason,
		RevokedAt:       time.Now().UTC(),
		RevokedUntil:    revokedUntil,
		RevokedBy:       revokedBy,
	}
	return nil
}

func (s *InMemoryRevocationStore) IsRevoked(class, epoch string) (bool, *RevocationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check class+epoch specific
	key := s.revocationKey(class, epoch)
	if entry, ok := s.store[key]; ok {
		if entry.RevokedUntil != nil && time.Now().UTC().After(*entry.RevokedUntil) {
			// Expired, treat as not revoked (consider cleanup later)
			return false, nil, nil
		}
		return true, &entry, nil
	}

	// Check class-wide (epoch = "")
	key = s.revocationKey(class, "")
	if entry, ok := s.store[key]; ok {
		if entry.RevokedUntil != nil && time.Now().UTC().After(*entry.RevokedUntil) {
			return false, nil, nil
		}
		return true, &entry, nil
	}

	return false, nil, nil
}

func (s *InMemoryRevocationStore) ListRevocations() ([]RevocationEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := make([]RevocationEntry, 0, len(s.store))
	for _, entry := range s.store {
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *InMemoryRevocationStore) UnrevokeClass(class, epoch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.revocationKey(class, epoch)
	delete(s.store, key)
	return nil
}

func (s *InMemoryRevocationStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = make(map[string]RevocationEntry)
	return nil
}

func (s *InMemoryRevocationStore) revocationKey(class, epoch string) string {
	if epoch == "" {
		return "revoke:" + class
	}
	return "revoke:" + class + ":" + epoch
}
