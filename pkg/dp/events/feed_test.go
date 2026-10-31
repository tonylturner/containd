// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFeedAppendOrderRetentionEpoch(t *testing.T) {
	s := NewStore(4)
	initial := s.ReadFeed(FeedRequest{TailOnly: true})
	for _, id := range []uint64{1 << 63, 4, 900, 2, 1} {
		s.Append(Event{ID: id, Kind: "routine", Timestamp: time.Unix(int64(id%100), 0)})
	}
	p := s.ReadFeed(FeedRequest{Epoch: initial.Epoch, Limit: 2})
	if p.Floor != 2 || p.Tail != 5 || len(p.Records) != 2 || p.Records[0].Offset != 2 || p.Records[0].Event.ID != 4 || p.Records[1].Event.ID != 900 {
		t.Fatalf("not append order: %+v", p)
	}
	p = s.ReadFeed(FeedRequest{Epoch: p.Epoch, After: 3, Limit: 2})
	if len(p.Records) != 2 || p.Records[0].Event.ID != 2 || p.Records[1].Event.ID != 1 {
		t.Fatal(p)
	}
	restarted := NewStore(4)
	restarted.Append(Event{ID: 1000})
	p = restarted.ReadFeed(FeedRequest{Epoch: initial.Epoch, After: 999})
	if p.Epoch == initial.Epoch || len(p.Records) != 1 || p.Records[0].Offset != 1 {
		t.Fatalf("restart did not invalidate offset: %+v", p)
	}
}

func TestFeedPriorityDoesNotStarveRoutine(t *testing.T) {
	s := NewStore(4)
	s.Append(Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"action": "DENY"}})
	start := s.ReadFeed(FeedRequest{TailOnly: true})
	for range 4 {
		s.Append(Event{Kind: "routine"})
	}
	if s.ListTelemetry(1)[0].Kind != "firewall.rule.hit" {
		t.Fatal("fixture must have an old priority DENY")
	}
	p := s.ReadFeed(FeedRequest{Epoch: start.Epoch, After: start.Tail})
	if p.Floor != 2 || len(p.Records) != 4 {
		t.Fatal(p)
	}
	for _, r := range p.Records {
		if r.Event.Kind != "routine" {
			t.Fatal(r)
		}
	}
}

func TestEventStringIdentity(t *testing.T) {
	for _, id := range []uint64{1<<53 + 1, 1<<63 + 1, 1<<63 + 2, ^uint64(0)} {
		e := Event{ID: id}
		raw, err := json.Marshal(e)
		if err != nil || !strings.Contains(string(raw), `"id":"`) {
			t.Fatalf("not a string: %s %v", raw, err)
		}
		var decoded Event
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded.ID != id {
			t.Fatalf("identity changed: %s %+v %v", raw, decoded, err)
		}
	}
	var e Event
	if err := json.Unmarshal([]byte(`{"id":9007199254740993}`), &e); err == nil {
		t.Fatal("numeric IDs must not survive the hard wire cutover")
	}
}
