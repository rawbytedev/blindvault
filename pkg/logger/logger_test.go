package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestFromContext(t *testing.T) {
	t.Run("returns global logger when no logger in context", func(t *testing.T) {
		ctx := context.Background()
		l := FromContext(ctx)
		require.NotNil(t, l)
	})

	t.Run("returns stored logger when present", func(t *testing.T) {
		ctx := context.Background()
		testLogger := zerolog.New(zerolog.NewTestWriter(t))
		ctx = WithLogger(ctx, &testLogger)
		l := FromContext(ctx)
		require.Equal(t, &testLogger, l)
	})
}

func TestLevelHelpers(t *testing.T) {
	buf := &bytes.Buffer{}
	origLogger := log.Logger
	defer func() { log.Logger = origLogger }()

	log.Logger = zerolog.New(buf).With().Timestamp().Logger()
	ctx := context.Background()

	tests := []struct {
		name  string
		logFn func(ctx context.Context) *zerolog.Event
		level string
		msg   string
	}{
		{"Info", Info, "info", "test info"},
		{"Debug", Debug, "debug", "test debug"},
		{"Warn", Warn, "warn", "test warn"},
		{"Error", Error, "error", "test error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFn(ctx).Msg(tt.msg)

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			require.NoError(t, err, "failed to parse JSON: %s", buf.String())

			require.Equal(t, tt.level, logEntry["level"])
			require.Equal(t, tt.msg, logEntry["message"])
		})
	}
}

func TestWithFields(t *testing.T) {
	buf := &bytes.Buffer{}
	origLogger := log.Logger
	defer func() { log.Logger = origLogger }()

	log.Logger = zerolog.New(buf).With().Timestamp().Logger()
	ctx := context.Background()

	fields := map[string]interface{}{
		"user_id": 123,
		"action":  "test",
	}
	ctx = With(ctx, fields)
	Info(ctx).Msg("test with fields")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	require.Equal(t, float64(123), logEntry["user_id"])
	require.Equal(t, "test", logEntry["action"])
	require.Equal(t, "test with fields", logEntry["message"])
}

func TestWithLoggerInContext(t *testing.T) {
	buf := &bytes.Buffer{}
	testLogger := zerolog.New(buf).With().Str("component", "test").Logger()
	ctx := WithLogger(context.Background(), &testLogger)

	Info(ctx).Msg("hello")

	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	require.Equal(t, "test", logEntry["component"])
	require.Equal(t, "hello", logEntry["message"])
}
