package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInMemoryNullifierStore(t *testing.T) {
	store := NewInMemoryNullifierStore().(*InMemoryNullifierStore)

	nullifier := []byte("test-nullifier")

	// First check should be new
	isNew, err := store.CheckAndStore(nullifier)
	require.NoError(t, err)
	require.True(t, isNew)

	// Second check should be existing
	isNew, err = store.CheckAndStore(nullifier)
	require.NoError(t, err)
	require.False(t, isNew)

	// Different nullifier should be new
	nullifier2 := []byte("another")
	isNew, err = store.CheckAndStore(nullifier2)
	require.NoError(t, err)
	require.True(t, isNew)

	// Close should work
	err = store.Close()
	require.NoError(t, err)
}
