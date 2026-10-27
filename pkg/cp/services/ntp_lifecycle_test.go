// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestNTPConcurrentApplyAndStatus(t *testing.T) {
	m := NewNTPManager(t.TempDir())
	m.Supervise = false
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				if err := m.Apply(context.Background(), config.NTPConfig{}); err != nil {
					t.Error(err)
				}
				m.Status()
				m.Current()
			}
		})
	}
	wg.Wait()
}
