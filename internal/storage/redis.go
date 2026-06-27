package storage

import (
	"blindvault/pkg/metrics"
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisNullifierStore struct {
	client     *redis.Client
	ctx        context.Context
	expiration time.Duration
	metrics    metrics.MetricsReporter
}

func NewRedisNullifierStore(addr, password string, db int, expiration time.Duration, metrics metrics.MetricsReporter) (*RedisNullifierStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisNullifierStore{
		client:     client,
		ctx:        ctx,
		expiration: expiration,
		metrics:    metrics,
	}, nil
}

func (s *RedisNullifierStore) CheckAndStore(nullifier []byte) (bool, error) {
	key := string(nullifier)

	// SETNX atomically sets the key only if it doesn't exist.
	// Returns true if set, false if already exists.
	ok, err := s.client.SetNX(s.ctx, key, "1", s.expiration).Result()
	if err != nil {
		s.metrics.RecordNullifierStore("setnx", "failure")
		return false, err
	}

	// ok is true → nullifier is new (first redemption)
	// ok is false → nullifier already exists (replay attempt)
	s.metrics.RecordNullifierStore("setnx", "success")
	return ok, nil
}

func (s *RedisNullifierStore) SetExpiration(expiration time.Duration) {
	s.expiration = expiration
}

func (s *RedisNullifierStore) Close() error {
	return s.client.Close()
}
