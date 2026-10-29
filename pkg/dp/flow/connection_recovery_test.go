// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"testing"
	"time"
)

func TestConnectionRecoveryElapsedWithoutCoverage(t *testing.T) {
	c := &Connection{}
	at := time.Now()
	if !c.CorrelationRecoveryElapsed(at) || c.CorrelationAvailable(at) {
		t.Fatal("no-loss history confused recovery with SYN coverage")
	}
	c.LoseCorrelation(at, time.Minute)
	c.LoseCorrelation(at.Add(time.Second), time.Minute)
	if c.CorrelationRecoveryElapsed(at.Add(time.Minute)) ||
		!c.CorrelationRecoveryElapsed(at.Add(time.Minute+time.Second)) {
		t.Fatal("recovery did not retain the latest loss deadline")
	}
	if c.CorrelationAvailable(at.Add(2 * time.Minute)) {
		t.Fatal("elapsed recovery manufactured SYN coverage")
	}
	c.Coverage().Store(true)
	if !c.CorrelationAvailable(at.Add(2 * time.Minute)) {
		t.Fatal("covered history did not recover")
	}
}
