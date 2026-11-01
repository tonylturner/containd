// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestLossScope(t *testing.T) {
	wire := Tuple{Source: Endpoint{IP: "192.0.2.1", Port: 40000}, Destination: Endpoint{IP: "192.0.2.2", Port: 502}, Transport: "tcp"}
	scope := LossScope{Source: wire.Source, Destination: wire.Destination, Transport: "tcp", Ports: true}
	reverse := scope
	reverse.Source, reverse.Destination = scope.Destination, scope.Source
	host := scope
	host.Ports = false
	host.Source.Port++
	otherPort := scope
	otherPort.Source.Port++
	otherHost := scope
	otherHost.Source.IP = "192.0.2.3"
	otherProtocol := scope
	otherProtocol.Transport = "udp"
	for _, tc := range []struct {
		name string
		loss CollectionLoss
		want bool
	}{
		{"known connection", CollectionLoss{ConnectionID: "a"}, true},
		{"other incarnation", CollectionLoss{ConnectionID: "b"}, false},
		{"tuple", CollectionLoss{Scope: scope}, true},
		{"reverse", CollectionLoss{Scope: reverse}, true},
		{"host pair", CollectionLoss{Scope: host}, true},
		{"other port", CollectionLoss{Scope: otherPort}, false},
		{"other host", CollectionLoss{Scope: otherHost}, false},
		{"other protocol", CollectionLoss{Scope: otherProtocol}, false},
		{"unknown", CollectionLoss{}, true},
		{"legacy interval", CollectionLoss{Start: time.Unix(1000, 0), End: time.Unix(1001, 0)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.loss.Code = "loss"
			ds := Dataset{}
			ds.RecordLoss(tc.loss)
			raw, err := json.Marshal(ds)
			if err != nil {
				t.Fatal(err)
			}
			ds = Dataset{}
			if err = json.Unmarshal(raw, &ds); err != nil {
				t.Fatal(err)
			}
			if got := ds.LossTouches("a", wire); got != tc.want {
				t.Fatalf("LossTouches=%v want %v", got, tc.want)
			}
		})
	}
}

func TestLegacyGapCannotAcquireNarrowerScope(t *testing.T) {
	ds := Dataset{Gaps: []string{"old"}}
	ds.RecordLoss(CollectionLoss{Code: "old", ConnectionID: "a"})
	ds.RecordLoss(CollectionLoss{Code: "old", ConnectionID: "a"})
	if len(ds.Losses) != 2 || !ds.LossTouches("b", Tuple{}) {
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
	if len(ds.Losses) != 1 || !ds.LossTouches("clean", Tuple{}) {
		t.Fatal("loss cap failed closed", ds)
	}
}
func TestOutcomeLossDoesNotExclude(t *testing.T) {
	ds := Dataset{}
	ds.RecordLoss(CollectionLoss{Code: "outcome_loss"})
	ds.RecordLoss(CollectionLoss{Code: "capture_unrelated"})
	if ds.LossTouches("any", Tuple{}) {
		t.Fatal("non-authority outcome excluded connection")
	}
}

func TestCoordinateLossDedupe(t *testing.T) {
	ds := Dataset{}
	a := CollectionLoss{Code: "capture_loss", Scope: LossScope{
		Source:      Endpoint{IP: "::ffff:192.0.2.1", Port: 1},
		Destination: Endpoint{IP: "192.0.2.2", Port: 2}, Transport: "tcp",
	}}
	b := a
	b.Scope.Source, b.Scope.Destination = a.Scope.Destination, a.Scope.Source
	b.Scope.Source.Port, b.Scope.Destination.Port = 30000, 502
	ds.RecordLoss(a)
	ds.RecordLoss(b)
	if len(ds.Losses) != 1 || ds.Losses[0].Scope.Source.IP != "192.0.2.1" || ds.Losses[0].Scope.Source.Port != 0 {
		t.Fatal("equivalent host-pair scopes duplicated", ds)
	}
}
