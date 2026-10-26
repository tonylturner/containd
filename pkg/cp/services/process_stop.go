// SPDX-License-Identifier: Apache-2.0
package services

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// done is closed by the sole cmd.Wait owner, before it acquires manager locks.
// A successful stop means the child was reaped, not merely signalled.
func stopManagedProcess(proc *os.Process, done <-chan struct{}) error {
	if proc == nil {
		return nil
	}
	if done == nil {
		return errors.New("managed process has no exit notification")
	}
	select {
	case <-done:
		return nil
	default:
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("terminate process: %w", err)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
	}
	if err := proc.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("kill process: %w", err)
	}
	timer.Reset(2 * time.Second)
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("process did not exit after kill")
	}
}
