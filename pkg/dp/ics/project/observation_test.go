// SPDX-License-Identifier: Apache-2.0
package project

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/evidence"
	"reflect"
	"testing"
	"time"
)

func TestObservationUsesDecodedProjector(t *testing.T) {
	unit, fc := uint8(0), uint8(3)
	o := evidence.Observation{SchemaVersion: evidence.SchemaVersion, DatasetID: "test", Source: evidence.SourcePCAP, ConnectionID: "c", ParentID: "p", CapturedAt: time.Unix(123, 0), Service: evidence.ServiceKey{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ServerPort: 502, Transport: "tcp", Direction: "request", Protocol: "modbus", Coordinates: evidence.CoordinatesWire}, Quality: evidence.Quality{Complete: true, Decoded: true}, Modbus: &evidence.Modbus{UnitID: &unit, FunctionCode: &fc, Spans: []evidence.Span{{First: 4, Last: 6, Role: "read"}}}}
	contexts, err := Observation(o)
	if err != nil {
		t.Fatal(err)
	}
	actual := Objects(&flow.State{}, dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{"unit_id": unit, "function_code": fc, "is_write": false, "address": uint16(4), "quantity": uint16(3)}}, nil)
	if len(contexts) != 1 || !reflect.DeepEqual(*contexts[0].ICS, actual[0]) {
		t.Fatalf("different projections: %+v %+v", contexts, actual)
	}
}
