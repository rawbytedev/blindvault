package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRedisNullifierStore(t *testing.T) {
	client, err := NewRedisClient("localhost:6379", "", 15)
	require.NoError(t, err)
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available, skipping test")
	}
	defer client.Close()
	// metrics can be nil for testing
	store, err := NewRedisNullifierStore("localhost:6379", "", 15, 2*time.Second)
	require.NoError(t, err)

	nullifier := []byte("test-redis-nullifier")
	isNew, err := store.CheckAndStore(t.Context(), nullifier)
	require.NoError(t, err)
	require.True(t, isNew)

	isNew, err = store.CheckAndStore(t.Context(), nullifier)
	require.NoError(t, err)
	require.False(t, isNew)

	err = store.Close()
	require.NoError(t, err)
}
