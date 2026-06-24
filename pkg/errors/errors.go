package errors

import (
	"blindvault/pkg/logger"
	"context"
	"fmt"
)

// Wrap logs the error and returns a new error with the given message.
func Wrap(ctx context.Context, err error, msg string) error {
	logger.Error(ctx).Err(err).Msg(msg)
	return fmt.Errorf("%s: %w", msg, err)
}

// New logs a message and returns a new error.
func New(ctx context.Context, msg string) error {
	logger.Error(ctx).Msg(msg)
	return fmt.Errorf("%s", msg)
}
