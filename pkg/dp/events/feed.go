// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"crypto/rand"
)

// FeedRequest addresses append order, never event identity or wall time.
// TailOnly establishes a new destination's boundary without backfill.
type FeedRequest struct {
	Epoch    string
	After    uint64
	Limit    int
	TailOnly bool
}

// FeedRecord is one append in a store lifetime. Imported event IDs need not
// be monotonic or unique; Offset always is.
type FeedRecord struct {
	Offset uint64 `json:"offset,string"`
	Event  Event  `json:"event"`
}

// FeedPage is an atomic snapshot of the bounded forwarding ring. Floor is
// the first retained offset (Tail+1 if empty). An epoch change invalidates
// the requested offset and returns the earliest retained rows.
type FeedPage struct {
	Epoch   string       `json:"epoch"`
	Floor   uint64       `json:"floor,string"`
	Tail    uint64       `json:"tail,string"`
	Records []FeedRecord `json:"records"`
}

// FeedReader is the per-source forwarding capability.
type FeedReader func(context.Context, FeedRequest) (FeedPage, error)

func newFeedEpoch() string { return rand.Text() }

// ReadFeed reads oldest-first, independently of telemetry priority banks.
// Forward retention is bounded by the store capacity, even when browser
// evidence retains a DENY or incident longer.
func (s *Store) ReadFeed(q FeedRequest) FeedPage {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := FeedPage{Epoch: s.epoch, Tail: s.feedTail, Records: []FeedRecord{}}
	p.Floor = p.Tail - uint64(len(s.feed.events)) + 1
	if q.TailOnly {
		return p
	}
	if q.Epoch != p.Epoch {
		q.After = 0
	}
	if q.After >= p.Tail {
		return p
	}
	start := max(q.After+1, p.Floor)
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	for offset := start; offset <= p.Tail && len(p.Records) < limit; offset++ {
		p.Records = append(p.Records, FeedRecord{Offset: offset, Event: s.feed.at(int(offset - p.Floor))})
	}
	return p
}
