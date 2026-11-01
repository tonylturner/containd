// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/evidence"
)

// Outcome rendezvous is worker-owned and cannot block packet verdicts. The
// record, byte and age bounds also cover outcomes which arrive before decode.
const joinRecords = 4096
const joinBytes = 32 << 20
const joinTTL = 60 * time.Second

type pendingEvidence struct {
	parent      *evidence.Observation
	lease       *watchLease
	outcome     evidence.Outcome
	at          time.Time
	bytes       int
	collectedAt time.Time
}
type evidenceJoin struct {
	watch   *evidenceWatch
	ctx     context.Context
	entries map[string]*pendingEvidence
	bytes   int
}

func newEvidenceJoin(w *evidenceWatch, ctx context.Context) *evidenceJoin {
	return &evidenceJoin{watch: w, ctx: ctx, entries: map[string]*pendingEvidence{}}
}
func (j *evidenceJoin) write(lease *watchLease, parents []evidence.Observation, collectedAt time.Time) {
	if err := j.watch.flushLosses(j.ctx, lease); err != nil {
		j.watch.fail(err)
		return
	}
	_, err := j.watch.store.Ingest(j.ctx, evidence.IngestRequest{DatasetID: lease.dataset.ID, Parents: parents, CollectedAt: collectedAt})
	j.watch.fail(err)
}
func (j *evidenceJoin) finish(key string) {
	entry := j.entries[key]
	delete(j.entries, key)
	j.bytes -= entry.bytes
	if entry.parent != nil {
		entry.parent.Outcome = entry.outcome
		if entry.parent.Outcome.Delivery == "" {
			entry.parent.Outcome.Delivery = "unknown"
		}
		j.write(entry.lease, []evidence.Observation{*entry.parent}, entry.collectedAt)
	}
}
func (j *evidenceJoin) oldest() string {
	var key string
	var at time.Time
	for id, e := range j.entries {
		if key == "" || e.at.Before(at) || e.at.Equal(at) && id < key {
			key, at = id, e.at
		}
	}
	return key
}
func (j *evidenceJoin) entry(id string, lease *watchLease) *pendingEvidence {
	if e := j.entries[id]; e != nil {
		return e
	}
	for len(j.entries) >= joinRecords {
		j.finish(j.oldest())
	}
	e := &pendingEvidence{lease: lease, at: time.Now(), outcome: evidence.Outcome{Delivery: "unknown"}}
	j.entries[id] = e
	return e
}
func (j *evidenceJoin) account(key string) {
	entry := j.entries[key]
	j.bytes -= entry.bytes
	entry.bytes = 128 + len(key)
	if entry.parent != nil {
		p, _ := json.Marshal(entry.parent)
		entry.bytes += len(p)
	}
	o, _ := json.Marshal(entry.outcome)
	entry.bytes += len(o)
	j.bytes += entry.bytes
	for j.bytes > joinBytes && len(j.entries) > 0 {
		j.finish(j.oldest())
	}
}
func (j *evidenceJoin) accept(batch evidenceBatch) {
	for _, parent := range batch.parents {
		if parent.IEC104 == nil {
			j.write(batch.lease, []evidence.Observation{parent}, batch.collectedAt)
			continue
		}
		e := j.entry(parent.ParentID, batch.lease)
		p := parent
		e.parent = &p
		e.collectedAt = batch.collectedAt
		j.account(parent.ParentID)
	}
	for _, ev := range batch.outcomes {
		ids := []string{}
		if id, ok := eventfields.String(ev.Attributes, eventfields.KeyAPDUID); ok {
			ids = append(ids, id)
		}
		if values, ok := eventfields.Strings(ev.Attributes, eventfields.KeyAPDUIDs); ok {
			ids = append(ids, values...)
		}
		for _, id := range ids {
			e := j.entry(id, batch.lease)
			switch ev.Kind {
			case eventfields.KindDecision:
				d := evidence.Decision{}
				d.Decision, _ = eventfields.String(ev.Attributes, eventfields.KeyDecision)
				d.Mode, _ = eventfields.String(ev.Attributes, eventfields.KeyMode)
				d.RuleID, _ = eventfields.String(ev.Attributes, eventfields.KeyRuleID)
				d.ScopeID, _ = eventfields.String(ev.Attributes, "scopeId")
				d.Reason, _ = eventfields.String(ev.Attributes, eventfields.KeyReason)
				e.outcome.Decisions = append(e.outcome.Decisions, d)
			case eventfields.KindVerdict:
				outcome, _ := eventfields.String(ev.Attributes, eventfields.KeyOutcome)
				if outcome == "dropped" {
					e.outcome.Delivery = "blocked"
				}
			case "evidence.delivery":
				delivery, _ := eventfields.String(ev.Attributes, "delivery")
				if delivery == "delivered" {
					e.outcome.Delivery = "delivered"
				}
			}
			j.account(id)
		}
	}
}
func (j *evidenceJoin) expire(now time.Time) {
	for key, e := range j.entries {
		if !now.Before(e.at.Add(joinTTL)) {
			j.finish(key)
		}
	}
}
func (j *evidenceJoin) flushAll() {
	for len(j.entries) > 0 {
		j.finish(j.oldest())
	}
}
