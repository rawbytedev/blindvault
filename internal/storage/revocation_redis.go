package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rawbytedev/blindvault/pkg/logger"
	"github.com/redis/go-redis/v9"
)

// RevocationStore handles revocation state.
type RedisRevocationStore struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisRevocationStore(client *redis.Client) RevocationStore {
	return &RedisRevocationStore{
		client: client,
		ctx:    context.Background(),
	}
}

// NewRevocationStore creates a new revocation store.
func NewRevocationStore(addr, password string, db int) (RevocationStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &RedisRevocationStore{
		client: client,
		ctx:    context.Background(),
	}, nil
}

// RevokeClass marks a credential class as revoked.
func (s *RedisRevocationStore) RevokeClass(class, epoch, reason, revokedBy string, revokedUntil *time.Time) error {
	key := s.revocationKey(class, epoch)
	entry := RevocationEntry{
		CredentialClass: class,
		KeyEpoch:        epoch,
		Reason:          reason,
		RevokedAt:       time.Now().UTC(),
		RevokedUntil:    revokedUntil,
		RevokedBy:       revokedBy,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Store with TTL if revokedUntil is set
	var ttl time.Duration
	if revokedUntil != nil {
		ttl = time.Until(*revokedUntil)
		if ttl <= 0 {
			return fmt.Errorf("revoked_until must be in the future")
		}
	} else {
		ttl = 0 // no expiration (permanent)
		logger.Info(context.Background()).Msg("No TTL")
	}

	return s.client.Set(s.ctx, key, data, ttl).Err()
}

// IsRevoked checks if a credential is revoked.
func (s *RedisRevocationStore) IsRevoked(class, epoch string) (bool, *RevocationEntry, error) {
	// Check class+epoch specific revocation first
	key := s.revocationKey(class, epoch)
	data, err := s.client.Get(s.ctx, key).Bytes()
	if err == nil {
		var entry RevocationEntry
		if err := json.Unmarshal(data, &entry); err == nil {
			if entry.RevokedUntil != nil && time.Now().UTC().After(*entry.RevokedUntil) {
				return false, nil, nil
			}
			return true, &entry, nil
		}
	}

	// Check class-wide revocation (all epochs)
	key = s.revocationKey(class, "")
	data, err = s.client.Get(s.ctx, key).Bytes()
	if err == nil {
		var entry RevocationEntry
		if err := json.Unmarshal(data, &entry); err == nil {
			return true, &entry, nil
		}
	}

	return false, nil, nil
}

// ListRevocations returns all active revocation entries.
func (s *RedisRevocationStore) ListRevocations() ([]RevocationEntry, error) {
	keys, err := s.client.Keys(s.ctx, "revoke:*").Result()
	if err != nil {
		return nil, err
	}
	var entries []RevocationEntry
	for _, key := range keys {
		data, err := s.client.Get(s.ctx, key).Bytes()
		if err != nil {
			continue
		}
		var entry RevocationEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// UnrevokeClass removes a revocation.
func (s *RedisRevocationStore) UnrevokeClass(class, epoch string) error {
	key := s.revocationKey(class, epoch)
	return s.client.Del(s.ctx, key).Err()
}

func (s *RedisRevocationStore) Close() error {
	return s.client.Close()
}

func (s *RedisRevocationStore) revocationKey(class, epoch string) string {
	if epoch == "" {
		return fmt.Sprintf("revoke:%s:*", class)
	}
	return fmt.Sprintf("revoke:%s:%s", class, epoch)
}
