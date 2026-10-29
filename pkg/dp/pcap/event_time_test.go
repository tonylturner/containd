// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestAnalysisEventCaptureTime(t *testing.T) {
	raw := buildPCAP([][]byte{buildModbusEthernetFrame(1000)})
	at := time.Unix(1234567890, 654321000)
	binary.LittleEndian.PutUint32(raw[24:], uint32(at.Unix()))
	binary.LittleEndian.PutUint32(raw[28:], uint32(at.Nanosecond()/1000))
	result, err := Analyze(bytes.NewReader(raw), modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedEvents(result.Events)) != 1 {
		t.Fatal("fixture emitted no Modbus event")
	}
	for _, ev := range decodedEvents(result.Events) {
		if !ev.Timestamp.Equal(at) {
			t.Fatalf("event timestamp = %v, want %v", ev.Timestamp, at)
		}
	}
}
