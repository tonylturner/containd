// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"log/slog"
	"os"
)

func handleReloadSignals(ctx context.Context, mode string, signals <-chan os.Signal, reloads chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-signals:
			if !ok {
				return
			}
			if mode != "mgmt" && mode != "all" {
				slog.Info("SIGHUP: running configuration reload applies through management; environment and flags require restart", "mode", mode)
				continue
			}
			// Coalesce repeated signals while a bounded replay is in progress.
			select {
			case reloads <- struct{}{}:
			default:
			}
		}
	}
}
