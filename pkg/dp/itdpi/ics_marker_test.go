// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestMarkICSPreservesTimestamp(t *testing.T) {
	at := time.Unix(1234567890, 123)
	ev := dpi.Event{Proto: "modbus", Timestamp: at, Attributes: map[string]any{"unit_id": 1}}
	got := MarkICS(ev)
	if !got.Timestamp.Equal(at) || got.Attributes["ics"] != true {
		t.Fatalf("marked event = %+v", got)
	}
	if _, changed := ev.Attributes["ics"]; changed {
		t.Fatal("marking mutated the input attributes")
	}
}
