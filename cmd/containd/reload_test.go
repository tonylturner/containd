// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"os"
	"syscall"
	"testing"
)

func TestHandleReloadSignals(t *testing.T) {
	for _, mode := range []string{"mgmt", "all", "engine"} {
		t.Run(mode, func(t *testing.T) {
			signals := make(chan os.Signal, 2)
			signals <- syscall.SIGHUP
			signals <- syscall.SIGHUP
			close(signals)
			reloads := make(chan struct{}, 1)
			handleReloadSignals(context.Background(), mode, signals, reloads)
			want := 1
			if mode == "engine" {
				want = 0
			}
			if len(reloads) != want {
				t.Fatalf("queued reloads=%d want=%d", len(reloads), want)
			}
		})
	}
}
