// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"time"

	"github.com/tonylturner/containd/pkg/common/logging"
)

const (
	storeOpenMaxAttempts    = 6
	storeOpenInitialBackoff = 200 * time.Millisecond
	storeOpenMaxBackoff     = 2 * time.Second
)

var storeOpenSleep = time.Sleep
var storeOpenWarnf = func(format string, args ...any) {
	logging.NewService("mgmt").Warnf(format, args...)
}

func openStoreWithRetry[T any](name string, open func() (T, error)) (T, error) {
	var zero T
	backoff := storeOpenInitialBackoff
	for attempt := 1; attempt <= storeOpenMaxAttempts; attempt++ {
		store, err := open()
		if err == nil {
			return store, nil
		}
		if attempt == storeOpenMaxAttempts {
			return zero, err
		}

		storeOpenWarnf("%s store open failed (attempt %d/%d), retrying in %s: %v", name, attempt, storeOpenMaxAttempts, backoff, err)
		storeOpenSleep(backoff)
		backoff *= 2
		if backoff > storeOpenMaxBackoff {
			backoff = storeOpenMaxBackoff
		}
	}
	return zero, nil
}
