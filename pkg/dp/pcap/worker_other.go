//go:build !linux

package pcap

import (
	"context"
	"errors"

	"github.com/containd/containd/pkg/cp/config"
)

type worker struct {
	dir   string
	iface string
	cfg   config.PCAPConfig
}

func newWorker(dir, iface string, cfg config.PCAPConfig) *worker {
	return &worker{dir: dir, iface: iface, cfg: cfg}
}

func (w *worker) run(ctx context.Context, mgr *Manager) error {
	return errors.New("pcap capture is only supported on linux")
}
