// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func previewZoneResolver(snap *rules.Snapshot, src, dst net.IP) (string, string) {
	return resolveZonesWithAddrs(snap, src, dst, func(name string) ([]net.Addr, error) {
		cidr := map[string]string{"cc0": "10.60.60.1/24", "rtu0": "10.30.30.1/24"}[name]
		if cidr == "" {
			return nil, fmt.Errorf("unknown test interface %q", name)
		}
		_, network, err := net.ParseCIDR(cidr)
		return []net.Addr{network}, err
	})
}

func TestPreviewRuleZones(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(100)}
	snap := &rules.Snapshot{ZoneIfaces: map[string][]string{"control": {"cc0"}, "plant": {"rtu0"}}}
	e.ruleSnap.Store(snap)
	for _, forward := range []bool{true, false} {
		kind := "request"
		if !forward {
			kind = "response"
		}
		e.eventStore.Append(iecEvent(0, kind, forward,
			map[string]any{"apci_type": "I", "direction": kind, "type_id": uint8(46), "ca": uint16(1), "class": "control"}))
	}
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		for _, tc := range []struct {
			name     string
			src, dst []string
			want     int
		}{
			{"scoped", []string{"control"}, []string{"plant"}, 2},
			{"unknown source", []string{"unknown"}, []string{"plant"}, 0},
			{"unknown destination", []string{"control"}, []string{"unknown"}, 0},
			{"wrong orientation", []string{"plant"}, []string{"control"}, 0},
			{"unscoped", nil, nil, 2},
		} {
			t.Run(string(action)+"/"+tc.name, func(t *testing.T) {
				entry := rules.Entry{Action: action, SourceZones: tc.src, DestZones: tc.dst,
					ICS: rules.ICSPredicate{Protocol: "iec104"}}
				got := e.previewRule(entry, previewZoneResolver)
				if got.MatchCount != tc.want || got.TotalEvents != 2 {
					t.Fatalf("preview = %+v, want %d", got, tc.want)
				}
			})
		}
	}
	entry := rules.Entry{SourceZones: []string{"control"}, DestZones: []string{"plant"},
		Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104"}}
	e.ruleSnap.Store(&rules.Snapshot{ZoneIfaces: map[string][]string{"control": {"missing"}}})
	if got := e.previewRule(entry, previewZoneResolver); got.MatchCount != 0 {
		t.Fatalf("preview ignored current snapshot: %+v", got)
	}
}

func TestPreviewRuleIEC104RuntimeParity(t *testing.T) {
	evs := []events.Event{
		iecEvent(0, "request", true, map[string]any{"apci_type": "I", "direction": "request", "type_id": uint8(100), "ca": uint16(1)}),
		iecEvent(0, "response", false, map[string]any{"apci_type": "I", "direction": "response", "type_id": uint8(1), "ca": uint16(1)}),
		iecEvent(0, "request", true, map[string]any{"apci_type": "I", "direction": "request", "type_id": uint8(46), "ca": uint16(1)}),
		iecEvent(0, "response", false, map[string]any{"apci_type": "I", "direction": "response", "type_id": uint8(46), "ca": uint16(1)}),
		iecEvent(0, "unsupported", true, map[string]any{"apci_type": "I", "direction": "request", "type_id": uint8(2), "ca": uint16(1)}),
		iecEvent(0, "request", true, map[string]any{"apci_type": "I", "direction": "request", "type_id": uint8(100), "ca": uint16(65535)}),
		iecEvent(0, "malformed", true, nil),
	}
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		for _, readOnly := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/readOnly=%t", action, readOnly), func(t *testing.T) {
				entry := rules.Entry{ID: "candidate", Action: action, SourceZones: []string{"control"}, DestZones: []string{"plant"},
					ICS: rules.ICSPredicate{Protocol: "iec104", ReadOnly: readOnly, Mode: "enforce"}}
				snap := &rules.Snapshot{Firewall: []rules.Entry{entry},
					ZoneIfaces: map[string][]string{"control": {"cc0"}, "plant": {"rtu0"}}}
				table := newIECTable("enforce")
				table.policy = newRulesPolicy(snap)
				client, _ := addrPort(net.ParseIP(evs[0].SrcIP), evs[0].SrcPort)
				server, _ := addrPort(net.ParseIP(evs[0].DstIP), evs[0].DstPort)
				s := &iecSession{ctx: iecSessionContext(snap, client, server, previewZoneResolver), mode: "enforce"}
				e := &Engine{eventStore: events.NewStore(100)}
				e.ruleSnap.Store(snap)
				want := 0
				for _, ev := range evs {
					e.eventStore.Append(ev)
					decision := table.decideLocked(s, dpi.Event{Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes})
					if decision.ruleID == entry.ID {
						want++
					}
				}
				got := e.previewRule(entry, previewZoneResolver)
				if got.MatchCount != want || want == 0 {
					t.Fatalf("preview=%d runtime=%d", got.MatchCount, want)
				}
			})
		}
	}
}

func TestPreviewRuleUSUsesRuntimeContext(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			key := flow.Key{SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"),
				SrcPort: 40000, DstPort: 502, Proto: 6}
			if reverse {
				key = key.Reversed()
			}
			ev := events.Event{FlowID: key.Hash(), Proto: "modbus", Kind: "request",
				SrcIP: key.SrcIP.String(), DstIP: key.DstIP.String(), SrcPort: key.SrcPort, DstPort: key.DstPort,
				Transport: "tcp", Timestamp: time.Unix(123, 0),
				Attributes: map[string]any{"function_code": uint8(3), "is_write": false, "unit_id": uint8(1)}}
			entry := rules.Entry{Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus", ReadOnly: true}}
			snap := &rules.Snapshot{ZoneIfaces: map[string][]string{"control": {"cc0"}, "plant": {"rtu0"}}}
			got, ok := previewEventContext(snap, entry, ev, previewZoneResolver)
			want, runtimeOK := evalContextFromDPIEvent(snap, &flow.State{Key: key},
				&dpi.ParsedPacket{Proto: "tcp", SrcPort: key.SrcPort, DstPort: key.DstPort},
				dpi.Event{Proto: ev.Proto, Kind: ev.Kind, Attributes: ev.Attributes}, "control", "plant")
			want.Now = ev.Timestamp
			if !ok || !runtimeOK || !reflect.DeepEqual(got, want) {
				t.Fatalf("preview context %+v != runtime %+v", got, want)
			}
			if !rules.PreviewMatch(entry, got) {
				t.Fatal("read-only Modbus rule did not match")
			}
		})
	}
}

func TestPreviewRuleIEC104EqualPorts(t *testing.T) {
	ev := iecEvent(0, "response", false, map[string]any{
		"apci_type": "I", "direction": "response", "type_id": uint8(1), "ca": uint16(1),
	})
	ev.DstPort = iec104Port // client and server both use 2404
	e := &Engine{eventStore: events.NewStore(10)}
	e.eventStore.Append(ev)
	got := e.PreviewRule(rules.Entry{Action: rules.ActionAllow, Sources: []string{ev.DstIP + "/32"},
		Destinations: []string{ev.SrcIP + "/32"}, ICS: rules.ICSPredicate{Protocol: "iec104", ReadOnly: true}})
	if got.MatchCount != 1 {
		t.Fatalf("lost session orientation with equal ports: %+v", got)
	}
}

func TestPreviewRuleEnvelopeDenialsNeverMatch(t *testing.T) {
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		for _, kind := range []string{"unsupported", "malformed", "request"} {
			t.Run(string(action)+"/"+kind, func(t *testing.T) {
				e := &Engine{eventStore: events.NewStore(10)}
				ca := uint16(1)
				if kind == "request" {
					ca = 65535
				}
				e.eventStore.Append(iecEvent(0, kind, true, map[string]any{
					"apci_type": "I", "direction": "request", "type_id": uint8(100), "ca": ca,
				}))
				got := e.PreviewRule(rules.Entry{Action: action, ICS: rules.ICSPredicate{Protocol: "iec104"}})
				if got.MatchCount != 0 {
					t.Fatalf("envelope denial counted as rule match: %+v", got)
				}
			})
		}
	}
}

func TestPreviewRuleWindowAndSamples(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(6000)}
	entry := rules.Entry{Action: rules.ActionAllow, SourceZones: []string{"control"}, DestZones: []string{"plant"},
		Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}}
	for i := 1; i <= 5100; i++ {
		e.eventStore.Append(events.Event{SrcIP: "10.60.60.10", DstIP: "10.30.30.30",
			Transport: "tcp", DstPort: 502, Timestamp: time.Unix(int64(i), 0)})
	}
	e.ruleSnap.Store(&rules.Snapshot{ZoneIfaces: map[string][]string{"control": {"cc0"}, "plant": {"rtu0"}}})
	got := e.previewRule(entry, previewZoneResolver)
	if got.MatchCount != 5000 || got.TotalEvents != 5000 || len(got.SampleMatches) != 50 ||
		!got.TimeRange.Start.Equal(time.Unix(101, 0)) || !got.TimeRange.End.Equal(time.Unix(5100, 0)) {
		t.Fatalf("preview = %+v", got)
	}
	if e.eventStore.Len() != 5100 || e.ruleSnap.Load().Firewall != nil {
		t.Fatal("preview mutated live state")
	}
}

func TestPreviewRuleEmpty(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(10)}
	got := e.PreviewRule(rules.Entry{})
	if got.MatchCount != 0 || got.TotalEvents != 0 || got.TimeRange != nil || got.SampleMatches == nil {
		t.Fatalf("empty preview = %+v", got)
	}
}

// TestPreviewRuleZoneWarnings checks that the preview warns about a zone
// only when the running configuration assigns it no interface.
func TestPreviewRuleZoneWarnings(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(10)}
	e.ruleSnap.Store(&rules.Snapshot{ZoneIfaces: map[string][]string{"control": {"cc0"}, "plant": {"rtu0"}}})
	bound := rules.Entry{ID: "bound", Action: rules.ActionAllow, SourceZones: []string{"control"}, DestZones: []string{"plant"}}
	if got := e.previewRule(bound, previewZoneResolver).Warnings; len(got) != 0 {
		t.Fatalf("bound zones warned: %+v", got)
	}
	empty := rules.Entry{ID: "empty", Action: rules.ActionAllow, SourceZones: []string{"control"}, DestZones: []string{"dmz"}}
	got := e.previewRule(empty, previewZoneResolver).Warnings
	if len(got) != 1 || got[0].Predicate != enforce.PredicateZone || !reflect.DeepEqual(got[0].Zones, []string{"dmz"}) {
		t.Fatalf("empty zone warnings = %+v, want one zone warning for dmz", got)
	}
}
