//go:build windows && (windows_integration || all_platform)

package trustinstall

import (
	"context"
	"time"
)

func waitUntil(ctx context.Context, interval time.Duration, fn func() (bool, error)) error {
	for {
		ok, err := fn()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
