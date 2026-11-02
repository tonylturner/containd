// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"go.uber.org/zap"
)

const engineSyncHealthTimeout = time.Second

// startConvergence runs the sole coordinator and joins it before callers close
// stores. ErrDrain is returned to assembly: stores must remain open when an
// uncooperative worker still owns them.
func startConvergence(ctx context.Context, coordinator convergence.Coordinator, logger *zap.SugaredLogger, diagnostics <-chan error) func() error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	diagnosticsDone := make(chan struct{})
	go func() {
		defer close(diagnosticsDone)
		previous := ""
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-diagnostics:
				if err != nil && err.Error() != previous {
					logger.Warnf("runtime convergence: %v", err)
					previous = err.Error()
				}
			}
		}
	}()
	go func() { done <- coordinator.Run(ctx) }()
	return func() error {
		cancel()
		err := <-done
		<-diagnosticsDone
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
}
