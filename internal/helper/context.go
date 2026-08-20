package helper

import (
	"context"

	"github.com/rawbytedev/blindvault/pkg/errors"
)

func CheckContext(ctx context.Context, err string) error {
	select {
	case <-ctx.Done():
		return errors.Wrap(ctx, ctx.Err(), err)
	default:
		return nil
	}
}
