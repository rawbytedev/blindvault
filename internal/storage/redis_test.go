package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRedisNullifierStore(t *testing.T) {
	client, err := NewRedisClient("localhost:6379", "", 15)
	if err != nil {
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

	NullStore, ok := store.(*RedisNullifierStore)
	require.True(t, ok, "Assertion failed")
	err = NullStore.Ping(context.Background())
	require.NoError(t, err)
	NullStore.SetExpiration(1 * time.Second)
	// time.Sleep(2 * time.Second) // Wait for the nullifier to expire
	isNew, err = store.CheckAndStore(t.Context(), nullifier)
	time.Sleep(2 * time.Second)
	require.NoError(t, err)
	require.False(t, isNew)

	// Run the check again after expiration to ensure it can be stored again
	// without explicitly waiting for expiration in the test
	isNew, err = store.CheckAndStore(t.Context(), nullifier)
	require.NoError(t, err)
	require.True(t, isNew)

	err = store.Close()
	require.NoError(t, err)
}
