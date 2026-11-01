// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
)

// SocketFaults exposes only real socket closure and subsequent open failures
// to the external kernel test. No source notifications are synthesized.
type SocketFaults struct {
	QueueClose, LogClose   chan func() error
	RejectQueue, RejectLog atomic.Bool
}

func InstallSocketFaults(t *testing.T) *SocketFaults {
	t.Helper()
	f := &SocketFaults{QueueClose: make(chan func() error, 16), LogClose: make(chan func() error, 16)}
	queueOpen, logOpen := openNFQueue, openNFLog
	initial, maximum, attempts := nfqueueRetryInitial, nfqueueRetryMax, nfqueueMaxRetries
	t.Cleanup(func() {
		openNFQueue, openNFLog = queueOpen, logOpen
		nfqueueRetryInitial, nfqueueRetryMax, nfqueueMaxRetries = initial, maximum, attempts
	})
	nfqueueRetryInitial, nfqueueRetryMax, nfqueueMaxRetries = time.Millisecond, time.Millisecond, 3
	openNFQueue = func(cfg *nfqueue.Config) (*nfqueue.Nfqueue, error) {
		if f.RejectQueue.Load() {
			return nil, errors.New("queue re-registration unavailable")
		}
		q, err := queueOpen(cfg)
		if err == nil {
			f.QueueClose <- q.Con.Close
		}
		return q, err
	}
	openNFLog = func(group uint16) (nfLogHandle, error) {
		if f.RejectLog.Load() {
			return nil, errors.New("logging re-registration unavailable")
		}
		log, err := logOpen(group)
		if err == nil {
			f.LogClose <- log.(*nfLogReceiver).conn.Close
		}
		return log, err
	}
	return f
}
