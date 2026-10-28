// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

// Stored HTTP events, which the events API and exports serve, hold parsed
// metadata only: no header or body bytes of the decoded packet.
func TestRecordedHTTPEventsHoldNoPayloadBytes(t *testing.T) {
	store := events.NewStore(16)
	e, err := New(Config{Events: store})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 12345, DstPort: 80, Proto: 6,
	}, time.Now())
	pkt := &dpi.ParsedPacket{
		Payload: []byte("POST /login HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer SECRET\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n\r\npassword=SECRET"),
		Proto: "tcp", SrcPort: 12345, DstPort: 80,
	}
	evs, err := itdpi.NewHTTPDecoder().OnPacket(state, pkt)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events=%d err=%v", len(evs), err)
	}
	e.RecordDPIEvents(state, pkt, evs)

	list := store.List(0)
	if len(list) != 1 || list[0].Proto != "http" || list[0].Kind != "request" {
		t.Fatalf("stored events = %+v", list)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("stored event leaks payload bytes: %s", raw)
	}
	if _, ok := list[0].Attributes["preview"]; ok {
		t.Fatalf("stored event carries a payload preview: %+v", list[0].Attributes)
	}
	if list[0].Attributes["method"] != "POST" || list[0].Attributes["path"] != "/login" {
		t.Fatalf("parsed metadata missing: %+v", list[0].Attributes)
	}
}
