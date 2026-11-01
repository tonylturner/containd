// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"testing"
	"time"
)

func TestLossScope(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	for _, tc := range []struct {
		name        string
		loss        CollectionLoss
		first, last time.Time
		want        bool
	}{
		{"known connection", CollectionLoss{ConnectionID: "a"}, at, at, true},
		{"other incarnation", CollectionLoss{ConnectionID: "b"}, at, at, false},
		{"inclusive start", CollectionLoss{Start: at, End: at.Add(time.Second)}, at.Add(-time.Second), at, true},
		{"inclusive end", CollectionLoss{Start: at, End: at.Add(time.Second)}, at.Add(time.Second), at.Add(2 * time.Second), true},
		{"before", CollectionLoss{Start: at, End: at.Add(time.Second)}, at.Add(-time.Second), at.Add(-time.Nanosecond), false},
		{"after", CollectionLoss{Start: at, End: at.Add(time.Second)}, at.Add(2 * time.Second), at.Add(3 * time.Second), false},
		{"unknown", CollectionLoss{}, at, at, true},
		{"partial interval", CollectionLoss{Start: at}, at, at, true},
		{"reversed interval", CollectionLoss{Start: at.Add(time.Second), End: at}, at, at, true},
		{"missing capture time", CollectionLoss{Start: at, End: at}, time.Time{}, at, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.loss.Code = "loss"
			ds := Dataset{}
			ds.RecordLoss(tc.loss)
			if got := ds.LossTouches("a", tc.first, tc.last); got != tc.want {
				t.Fatalf("LossTouches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLegacyGapCannotAcquireNarrowerScope(t *testing.T) {
	ds := Dataset{Gaps: []string{"old"}}
	ds.RecordLoss(CollectionLoss{Code: "old", ConnectionID: "a"})
	ds.RecordLoss(CollectionLoss{Code: "old", ConnectionID: "a"})
	if len(ds.Losses) != 2 || !ds.LossTouches("b", time.Now(), time.Now()) {
		t.Fatalf("legacy gap narrowed by later localization: %+v", ds)
	}
}
