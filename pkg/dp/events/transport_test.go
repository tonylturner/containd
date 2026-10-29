// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportMetadataAndDirectionalGrouping(t *testing.T) {
	evidence := &conntrack.Evidence{ID: 12, TimeoutSeconds: 60,
		Original: conntrack.Tuple{Family: 2, Protocol: 6,
			Source: netip.MustParseAddrPort("192.0.2.1:41000"), Destination: netip.MustParseAddrPort("198.51.100.2:502")},
		Reply: conntrack.Tuple{Family: 2, Protocol: 6,
			Source: netip.MustParseAddrPort("198.51.100.2:502"), Destination: netip.MustParseAddrPort("198.51.100.1:52000")}}
	c := &flow.Connection{ID: "epoch/1", Key: "private", Status: "resolved", Evidence: evidence}
	store := NewStore(10)
	for i, tuple := range []conntrack.Tuple{evidence.Original, evidence.Reply} {
		state := flow.NewState(flow.TupleKey(tuple, flow.Direction(i)), time.Now())
		state.Connection.Store(c)
		event := dpi.Event{FlowID: state.Key.Hash(), Proto: "modbus", Kind: "request", Connection: c}
		data, err := json.Marshal(event)
		if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "Evidence") {
			t.Fatalf("internal evidence leaked: %s, %v", data, err)
		}
		store.Record(state, nil, []dpi.Event{event})
	}
	if summaries := store.Flows(0); len(summaries) != 2 || summaries[0].TransportConnectionID != c.ID || summaries[1].TransportConnectionID != c.ID {
		t.Fatalf("directional grouping changed: %+v", summaries)
	}
	for _, event := range store.List(0) {
		data, err := json.Marshal(event)
		if err != nil || !strings.Contains(string(data), `"transportConnectionId":"epoch/1"`) ||
			!strings.Contains(string(data), `"correlationStatus":"resolved"`) {
			t.Fatalf("public fields missing: %s, %v", data, err)
		}
	}
	first := store.List(0)[0]
	first.TransportConnectionID = "epoch/2"
	store.Append(first)
	for _, summary := range store.Flows(0) {
		if summary.FlowID == first.FlowID && (summary.TransportConnectionID != "" || summary.CorrelationStatus != "mixed") {
			t.Fatalf("reused wire tuple claimed a single incarnation: %+v", summary)
		}
	}
}
