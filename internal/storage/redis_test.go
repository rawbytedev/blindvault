package storage

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRedisNullifierStore(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}
	defer func() {
		if err := client.FlushDB(context.Background()).Err(); err != nil {
			t.Fatal("Flush Failed %w", err)
		}
	}()
	defer client.Close()

	// metrics can be nil for testing
	store, err := NewRedisNullifierStore("localhost:6379", "", 15, time.Hour, nil)
	require.NoError(t, err)

	nullifier := []byte("test-redis-nullifier")
	isNew, err := store.CheckAndStore(nullifier)
	require.NoError(t, err)
	require.True(t, isNew)

	isNew, err = store.CheckAndStore(nullifier)
	require.NoError(t, err)
	require.False(t, isNew)

	err = store.Close()
	require.NoError(t, err)
}
