//go:build !linux

package cli

import (
	"context"
	"fmt"
	"time"
)

func captureToPCAP(ctx context.Context, ifaceName string, duration time.Duration, outPath string) (int, error) {
	_ = ctx
	_ = ifaceName
	_ = duration
	_ = outPath
	return 0, fmt.Errorf("diag capture is only supported on linux")
}
