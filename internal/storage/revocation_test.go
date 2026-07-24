package storage

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestRevocationStore runs the full test suite against any RevocationStore implementation.
func TestRevocationStore(t *testing.T) {
	t.Run("InMemory", func(t *testing.T) {
		store := NewInMemoryRevocationStore()
		testRevocationStore(t, store)
	})

	t.Run("Redis", func(t *testing.T) {
		// Skip if no Redis available
		client := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
			DB:   15,
		})
		if err := client.Ping(context.Background()).Err(); err != nil {
			t.Skip("Redis not available, skipping Redis tests")
		}
		defer client.Close()

		store := NewRedisRevocationStore(client)
		testRevocationStore(t, store)
	})
}

func testRevocationStore(t *testing.T, store RevocationStore) {
	// Clean up after test
	t.Cleanup(func() {
		_ = store.Close()
	})

	class := "test_class"
	epoch := "2026-07"
	admin := "admin@example.com"
	reason := "security breach"

	t.Run("Revoke and Check", func(t *testing.T) {
		// Initially not revoked
		revoked, _, err := store.IsRevoked(class, epoch)
		require.NoError(t, err)
		require.False(t, revoked)

		// Revoke
		err = store.RevokeClass(class, epoch, reason, admin, nil)
		require.NoError(t, err)

		// Now revoked
		revoked, entry, err := store.IsRevoked(class, epoch)
		require.NoError(t, err)
		require.True(t, revoked)
		require.Equal(t, class, entry.CredentialClass)
		require.Equal(t, epoch, entry.KeyEpoch)
		require.Equal(t, reason, entry.Reason)
		require.Equal(t, admin, entry.RevokedBy)
	})

	t.Run("Revoke All Epochs", func(t *testing.T) {
		// Clean up from previous test
		_ = store.UnrevokeClass(class, epoch)

		// Revoke all epochs for this class
		err := store.RevokeClass(class, "", "all epochs", admin, nil)
		require.NoError(t, err)

		// Check that any epoch is revoked
		for _, e := range []string{"2026-07", "2026-08", "2025-12"} {
			revoked, _, err := store.IsRevoked(class, e)
			require.NoError(t, err)
			require.True(t, revoked, "epoch %s should be revoked", e)
		}
	})

	t.Run("Revoke with Expiration", func(t *testing.T) {
		_ = store.UnrevokeClass(class, epoch)

		// Revoke with 1 second expiration
		until := time.Now().UTC().Add(10 * time.Second)
		err := store.RevokeClass(class, epoch, "temporary", admin, &until)
		require.NoError(t, err)

		// Immediately revoked
		revoked, _, err := store.IsRevoked(class, epoch)
		require.NoError(t, err)
		require.True(t, revoked)
		if rstore, ok := store.(*RedisRevocationStore); ok {
			ttl, err := rstore.client.TTL(rstore.ctx, rstore.revocationKey(class, epoch)).Result()
			require.NoError(t, err)
			t.Logf("Redis TTL: %v", ttl)
		}
		// wait for revocation
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			revoked, _, err = store.IsRevoked(class, epoch)
			require.NoError(t, err)
			if !revoked {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.False(t, revoked, "key should have expired")
		// Now not revoked (expired)
		revoked, _, err = store.IsRevoked(class, epoch)
		require.NoError(t, err)
		require.False(t, revoked)
	})

	t.Run("List Revocations", func(t *testing.T) {
		// Clean up
		_ = store.UnrevokeClass(class, epoch)
		_ = store.UnrevokeClass(class, "")
		_ = store.UnrevokeClass("other_class", "")

		// Add some revocations
		err := store.RevokeClass(class, "2026-01", "reason1", "admin1", nil)
		require.NoError(t, err)
		err = store.RevokeClass(class, "2026-02", "reason2", "admin2", nil)
		require.NoError(t, err)
		err = store.RevokeClass("other_class", "", "reason3", "admin3", nil)
		require.NoError(t, err)

		entries, err := store.ListRevocations()
		require.NoError(t, err)
		require.Len(t, entries, 3)

		// Check entries exist
		found := map[string]bool{}
		for _, e := range entries {
			key := e.CredentialClass + ":" + e.KeyEpoch
			found[key] = true
		}
		require.True(t, found["other_class:"])
	})

	t.Run("Unrevoke", func(t *testing.T) {
		// Ensure it's revoked
		err := store.RevokeClass(class, epoch, "to be unrevoked", admin, nil)
		require.NoError(t, err)

		revoked, _, err := store.IsRevoked(class, epoch)
		require.NoError(t, err)
		require.True(t, revoked)

		// Unrevoke
		err = store.UnrevokeClass(class, epoch)
		require.NoError(t, err)

		revoked, _, err = store.IsRevoked(class, epoch)
		require.NoError(t, err)
		require.False(t, revoked)
	})
}

// TestRevocationStoreConcurrency tests concurrent access.
func TestRevocationStoreConcurrency(t *testing.T) {
	t.Run("InMemory", func(t *testing.T) {
		store := NewInMemoryRevocationStore()
		testConcurrentRevocation(t, store)
	})

	t.Run("Redis", func(t *testing.T) {
		client := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
			DB:   15,
		})
		if err := client.Ping(context.Background()).Err(); err != nil {
			t.Skip("Redis not available")
		}
		defer client.Close()

		store := NewRedisRevocationStore(client)
		testConcurrentRevocation(t, store)
	})
}

func testConcurrentRevocation(t *testing.T, store RevocationStore) {
	t.Cleanup(func() {
		_ = store.Close()
	})

	class := "concurrent_test"
	epoch := "2026-07"
	done := make(chan bool)

	// Concurrent revocations
	for i := 0; i < 10; i++ {
		go func(id int) {
			err := store.RevokeClass(class, epoch, "concurrent", "admin", nil)
			require.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all to finish
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should be revoked
	revoked, entry, err := store.IsRevoked(class, epoch)
	require.NoError(t, err)
	require.True(t, revoked)
	require.Equal(t, "concurrent", entry.Reason)
}
