// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"container/list"
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
	order       *list.Element
}
type evidenceJoin struct {
	watch       *evidenceWatch
	writer      *evidenceWatchWriter
	entries     map[string]*pendingEvidence
	order       list.List
	bytes       int
	writes      []evidence.Observation
	writeBytes  int
	writeLease  *watchLease
	collectedAt time.Time
}

func newEvidenceJoin(w *evidenceWatch, writer *evidenceWatchWriter) *evidenceJoin {
	return &evidenceJoin{watch: w, writer: writer, entries: map[string]*pendingEvidence{}}
}
func (j *evidenceJoin) write(lease *watchLease, parents []evidence.Observation, collectedAt time.Time) {
	for _, parent := range parents {
		data, err := json.Marshal(parent)
		if err != nil {
			j.watch.fail(err)
			return
		}
		if len(j.writes) > 0 && (j.writeLease != lease || len(j.writes) == 128 || j.writeBytes+len(data)+1 > (1<<20)-4096) {
			j.flushWrites()
		}
		j.writeLease = lease
		j.writes = append(j.writes, parent)
		j.writeBytes += len(data) + 1
		if collectedAt.After(j.collectedAt) {
			j.collectedAt = collectedAt
		}
	}
}
func (j *evidenceJoin) flushWrites() {
	if len(j.writes) == 0 {
		return
	}
	defer func() { j.writes = nil; j.writeBytes = 0; j.collectedAt = time.Time{} }()
	j.writer.submit(evidenceWrite{lease: j.writeLease, parents: j.writes, collectedAt: j.collectedAt, bytes: j.writeBytes + watchWriteOverhead})
}
func (j *evidenceJoin) finish(key string) {
	entry := j.entries[key]
	delete(j.entries, key)
	j.order.Remove(entry.order)
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
	if first := j.order.Front(); first != nil {
		return first.Value.(string)
	}
	return ""
}
func (j *evidenceJoin) entry(id string, lease *watchLease) *pendingEvidence {
	if e := j.entries[id]; e != nil {
		return e
	}
	for len(j.entries) >= joinRecords {
		j.finish(j.oldest())
	}
	e := &pendingEvidence{lease: lease, at: time.Now(), outcome: evidence.Outcome{Delivery: "unknown"}}
	e.order = j.order.PushBack(id)
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
	for len(j.entries) > 0 {
		key := j.oldest()
		if now.Before(j.entries[key].at.Add(joinTTL)) {
			break
		}
		j.finish(key)
	}
}
func (j *evidenceJoin) flushAll() {
	for len(j.entries) > 0 {
		j.finish(j.oldest())
	}
	j.flushWrites()
}
