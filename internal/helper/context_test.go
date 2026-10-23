package helper

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckContext(t *testing.T) {
	ctx, c := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer c()
	err := CheckContext(ctx)
	require.Nil(t, err, "CheckContext is supposed to return nil, unexpectedly returned %s", err)
	time.Sleep(5 * time.Millisecond)
	err = CheckContext(ctx)
	require.Error(t, err, "CheckContext is supposed to return err, unexpectedly returned nil")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	cancel()
	err = CheckContext(ctx)
	require.Error(t, err, "CheckContext is supposed to return err, unexpectedly returned nil")
}
