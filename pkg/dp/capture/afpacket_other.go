//go:build !linux

package capture

import (
	"context"
	"errors"
)

type worker struct {
	iface   string
	cfg     Config
	handler Handler
}

func (w *worker) run(ctx context.Context) error {
	_ = ctx
	return errors.New("afpacket capture is only supported on linux")
}
