// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"sync"

	"go.uber.org/zap"
)

// Listener faults describe this process's actual binds. They are boot-only
// diagnostics, not a reason to block a safe firewall apply or to claim recovery
// enforcement. Persisted config faults have their separate transactional gate.
type bootListenerFaults struct {
	mu     sync.Mutex
	faults []string
	logger *zap.SugaredLogger
}

func (f *bootListenerFaults) record(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = append(f.faults, err.Error())
	f.logger.Errorw("management.reservation.listener_fault", "error", err)
}

func (f *bootListenerFaults) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.faults...)
}
