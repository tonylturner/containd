// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"
	"time"
)

func TestMeterLifetimeOnly(t *testing.T) {
	var primary, errs meter
	primary.add(time.Now(), 5)
	primary.add(time.Now(), -2)
	errs.add(time.Now(), 1)
	status := meterStatus(&primary, &errs)
	if len(status) != 2 || status["count"] != 3 || status["errors_count"] != 1 {
		t.Fatal(status)
	}
	if !primary.active() || !primary.signed {
		t.Fatal("signed correction not recorded")
	}
	if got := meterStatus(nil, nil); got["count"] != 0 || got["errors_count"] != 0 {
		t.Fatal(got)
	}
}
