package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// captureLogs captures logs emitted during fn and returns the parsed log entry.
func captureLogs(t *testing.T, fn func()) map[string]interface{} {
	buf := &bytes.Buffer{}
	origLogger := log.Logger
	defer func() { log.Logger = origLogger }()

	log.Logger = zerolog.New(buf).With().Timestamp().Logger()

	fn()

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err, "failed to parse JSON log: %s", buf.String())
	return logEntry
}

func TestRunWithRecovery_Success(t *testing.T) {
	ctx := context.Background()
	workerName := "test-worker"

	// Worker function that returns nil
	fn := func(ctx context.Context) error {
		return nil
	}

	wrapped := RunWithRecovery(ctx, workerName, fn)
	err := wrapped()
	require.NoError(t, err)
}

func TestRunWithRecovery_ErrorPropagation(t *testing.T) {
	ctx := context.Background()
	workerName := "test-worker"
	expectedErr := errors.New("worker failed")

	fn := func(ctx context.Context) error {
		return expectedErr
	}

	wrapped := RunWithRecovery(ctx, workerName, fn)
	err := wrapped()
	require.Error(t, err)
	require.Equal(t, expectedErr, err)
}

func TestRunWithRecovery_PanicRecovery(t *testing.T) {
	ctx := context.Background()
	workerName := "panic-worker"

	fn := func(ctx context.Context) error {
		panic("something went wrong")
	}

	logEntry := captureLogs(t, func() {
		wrapped := RunWithRecovery(ctx, workerName, fn)
		err := wrapped()
		// After panic recovery, the function returns nil (no error propagated)
		require.NoError(t, err, "RunWithRecovery should not return an error after recovering panic")
	})

	// Verify the panic was logged correctly
	require.Equal(t, "error", logEntry["level"])
	require.Contains(t, logEntry["message"], "worker panicked")
	require.Equal(t, workerName, logEntry["worker"])
	require.Contains(t, logEntry["panic"], "something went wrong")
	require.Contains(t, logEntry["stack"], "worker_test.go") // stack trace contains test file
}

func TestRunWithRecovery_PanicWithNonError(t *testing.T) {
	ctx := context.Background()
	workerName := "panic-int-worker"

	fn := func(ctx context.Context) error {
		panic(42) // panic with int
	}

	logEntry := captureLogs(t, func() {
		wrapped := RunWithRecovery(ctx, workerName, fn)
		err := wrapped()
		require.NoError(t, err)
	})

	require.Equal(t, workerName, logEntry["worker"])
	require.Equal(t, float64(42), logEntry["panic"]) // JSON unmarshal converts int to float64
}

func TestRunWithRecovery_ContextPassedCorrectly(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "test-key", "test-value")

	workerName := "context-worker"

	fn := func(ctx context.Context) error {
		val := ctx.Value("test-key")
		if val != "test-value" {
			return errors.New("context value not propagated")
		}
		return nil
	}

	wrapped := RunWithRecovery(ctx, workerName, fn)
	err := wrapped()
	require.NoError(t, err)
}
