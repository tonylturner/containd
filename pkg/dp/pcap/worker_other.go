// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package pcap

import (
	"context"
	"errors"

	"github.com/tonylturner/containd/pkg/cp/config"
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
