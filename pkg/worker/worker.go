package worker

import (
	"context"
	"runtime/debug"

	"blindvault/pkg/logger"
)

// RunWithRecovery executes the given function in a goroutine and recovers from panics.
// It returns a function that can be passed to errgroup.Go.
// The returned error will contain the panic value and stack trace.
func RunWithRecovery(ctx context.Context, name string, fn func(ctx context.Context) error) func() error {
	return func() error {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(ctx).
					Interface("panic", r).
					Str("stack", string(debug.Stack())).
					Str("worker", name).
					Msg("worker panicked")
			}
		}()
		// Run the worker function. If it returns an error, it will be propagated.
		return fn(ctx)
	}
}
