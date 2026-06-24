package logger

import (
	"context"

	"github.com/rs/zerolog"
)

// Helper functions for each level
func Info(ctx context.Context) *zerolog.Event {
	return FromContext(ctx).Info()
}

func Debug(ctx context.Context) *zerolog.Event {
	return FromContext(ctx).Debug()
}

func Warn(ctx context.Context) *zerolog.Event {
	return FromContext(ctx).Warn()
}

func Error(ctx context.Context) *zerolog.Event {
	return FromContext(ctx).Error()
}

// With returns a new context with a logger that has the given fields added.
func With(ctx context.Context, fields map[string]any) context.Context {
	logger := FromContext(ctx).With().Fields(fields).Logger()
	return context.WithValue(ctx, loggerKey, &logger)
}

func Trace(ctx context.Context) *zerolog.Event {
	return FromContext(ctx).Trace()
}
