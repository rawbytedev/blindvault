package errors

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

func captureLogs(t *testing.T, fn func()) map[string]interface{} {
	buf := &bytes.Buffer{}
	origLogger := log.Logger
	defer func() { log.Logger = origLogger }()

	log.Logger = zerolog.New(buf).With().Timestamp().Logger()

	fn()

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err, "failed to parse JSON: %s", buf.String())
	return logEntry
}

func TestWrap(t *testing.T) {
	ctx := context.Background()
	origErr := errors.New("original error")
	logEntry := captureLogs(t, func() {
		err := Wrap(ctx, origErr, "wrapped message")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrapped message: original error")
	})

	require.Equal(t, "error", logEntry["level"])
	require.Contains(t, logEntry["message"], "wrapped message")
	require.Contains(t, logEntry["error"], "original error")
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	logEntry := captureLogs(t, func() {
		err := New(ctx, "new error message")
		require.Error(t, err)
		require.Equal(t, "new error message", err.Error())
	})

	require.Equal(t, "error", logEntry["level"])
	require.Equal(t, "new error message", logEntry["message"])
}
