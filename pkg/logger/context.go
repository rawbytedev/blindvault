// pkg/logger/context.go
package logger

import (
	"context"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ctxKey string

const loggerKey ctxKey = "logger"

// WithLogger returns a new context with the given logger attached.
func WithLogger(ctx context.Context, logger *zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext extracts the logger from context, or returns the global logger if none.
func FromContext(ctx context.Context) *zerolog.Logger {
	if l, ok := ctx.Value(loggerKey).(*zerolog.Logger); ok {
		return l
	}
	return &log.Logger
}

// WithRequestID returns a new context with a logger that has a request_id field.
// If a request_id is already present in the context, it reuses it.
func WithRequestID(ctx context.Context) (context.Context, string) {
	if reqID := ctx.Value("request_id"); reqID != nil {
		id := reqID.(string)
		logger := FromContext(ctx).With().Str("request_id", id).Logger()
		return WithLogger(ctx, &logger), id
	}
	id := uuid.New().String()
	logger := FromContext(ctx).With().Str("request_id", id).Logger()
	ctx = context.WithValue(ctx, "request_id", id) // store for later extraction
	return WithLogger(ctx, &logger), id
}
