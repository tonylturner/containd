// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"fmt"
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

func TestLossBoundAndTimeDedupe(t *testing.T) {
	ds := Dataset{}
	at := time.Now()
	ds.RecordLoss(CollectionLoss{Code: "drop", Start: at, End: at})
	data, err := json.Marshal(ds)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Dataset
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	roundtrip.RecordLoss(CollectionLoss{Code: "drop", Start: at.In(time.FixedZone("offset", 3600)), End: at})
	if len(roundtrip.Losses) != 1 {
		t.Fatal("JSON/location duplicated interval", roundtrip)
	}
	for i := range MaxLosses + 100 {
		ds.RecordLoss(CollectionLoss{Code: "drop", ConnectionID: fmt.Sprint(i)})
	}
	if len(ds.Losses) != 1 || !ds.LossTouches("clean", at, at) {
		t.Fatal("loss cap failed closed", ds)
	}
}
func TestOutcomeLossDoesNotExclude(t *testing.T) {
	ds := Dataset{}
	ds.RecordLoss(CollectionLoss{Code: "outcome_loss"})
	if ds.LossTouches("any", time.Now(), time.Now()) {
		t.Fatal("non-authority outcome excluded connection")
	}
}
