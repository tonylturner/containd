// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestBoundaryReplayIdentityPreservesEvaluatorInputs(t *testing.T) {
	a := evidence.Observation{CapturedAt: time.Unix(100, 0), Quality: evidence.Quality{Complete: true}, Service: evidence.ServiceKey{ServerPort: 502}}
	b := a
	b.CapturedAt = b.CapturedAt.Add(time.Hour)
	b.Outcome.Delivery = "blocked"
	b.ParentID = "second"
	key := func(o evidence.Observation, scheduled bool) string {
		t.Helper()
		k, err := boundaryReplayKey(o, scheduled)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	if key(a, false) != key(b, false) {
		t.Fatal("equivalent selector boundaries repeated")
	}
	if key(a, true) == key(b, true) {
		t.Fatal("scheduled replay lost capture time")
	}
	b = a
	b.Quality.Complete = false
	if key(a, false) == key(b, false) {
		t.Fatal("missing coverage conflated")
	}
	b = a
	b.Service.ServerPort++
	if key(a, false) == key(b, false) {
		t.Fatal("distinct evaluator inputs conflated")
	}
}
