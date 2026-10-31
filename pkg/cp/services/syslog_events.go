// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/evidence"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type eventProgress struct {
	gate       *sync.Mutex
	continuity uint64
	sent       uint64
	failed     uint64
	epoch      string
	offset     uint64
	tail       uint64
	lost       uint64
	historical bool
	err        string
	lastSent   time.Time
}

// SetEventFeeds replaces source capabilities, not their progress. Each reader
// must return append offsets and an atomic epoch/floor/tail snapshot. An absent
// engine capability is supplied as a failing reader, never a history fallback.
func (m *SyslogManager) SetEventFeeds(feeds map[evidence.Source]dpevents.FeedReader) {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	m.stopAndWait()
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feeds = maps.Clone(feeds)
	m.syncEventTargets()
	m.restartForwarder()
}

// syncEventTargets is called with eventMu and mu, after joining the worker.
// New destinations establish their boundary now, not at the first timer tick.
func (m *SyslogManager) syncEventTargets() {
	next := make(map[string]map[evidence.Source]eventProgress)
	for _, t := range syslogTargets(m.config.Forwarders) {
		next[t.id] = make(map[evidence.Source]eventProgress)
		for source, read := range m.feeds {
			st, exists := m.progress[t.id][source]
			if !exists {
				st.gate = &sync.Mutex{}
				ctx, cancel := context.WithTimeout(context.Background(), syslogDialTimeout)
				p, err := read(ctx, dpevents.FeedRequest{TailOnly: true})
				cancel()
				if err != nil {
					st.err, st.historical = "source unavailable", true
					st.continuity++
				} else {
					st.epoch, st.offset, st.tail = p.Epoch, p.Tail, p.Tail
				}
			}
			next[t.id][source] = st
		}
	}
	m.progress = next
}

// flushEvents bounds work independently per destination and source. Jobs run
// concurrently so a dead destination/source cannot hold up another's progress
// or the separately scheduled durable audit stream.
func (m *SyslogManager) flushEvents(ctx context.Context) {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	m.mu.Lock()
	targets := syslogTargets(m.config.Forwarders)
	feeds := maps.Clone(m.feeds)
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, t := range targets {
		for source, read := range feeds {
			wg.Go(func() { m.flushEventPair(ctx, t, source, read) })
		}
	}
	wg.Wait()
}

func (m *SyslogManager) flushEventPair(ctx context.Context, target syslogTarget, source evidence.Source, read dpevents.FeedReader) {
	m.mu.Lock()
	gate := m.progress[target.id][source].gate
	m.mu.Unlock()
	gate.Lock()
	defer gate.Unlock()
	m.mu.Lock()
	st := m.progress[target.id][source]
	format, batch := m.config.Format, m.batchSize
	m.mu.Unlock()
	if batch <= 0 {
		batch = 500
	}
	st, sent, failed := m.forwardEvents(ctx, target, source, read, st, format, batch)
	m.mu.Lock()
	defer m.mu.Unlock()
	st.sent += uint64(sent)
	st.failed += uint64(failed)
	m.progress[target.id][source] = st
	m.sentTotal += sent
	m.failTotal += failed
	m.lastBatch = sent
	m.lastFlush = time.Now().UTC()
	m.lastError, m.hitLimit = "", false
	for _, states := range m.progress {
		for _, state := range states {
			if state.err != "" {
				m.lastError = state.err
			}
			m.hitLimit = m.hitLimit || state.tail > state.offset
		}
	}
}

func (m *SyslogManager) forwardEvents(ctx context.Context, target syslogTarget, source evidence.Source, read dpevents.FeedReader, st eventProgress, format string, batch int) (eventProgress, int, int) {
	readCtx, cancel := context.WithTimeout(ctx, syslogDialTimeout)
	p, err := read(readCtx, dpevents.FeedRequest{Epoch: st.epoch, After: st.offset, Limit: batch, TailOnly: st.epoch == ""})
	cancel()
	if err != nil {
		st.err, st.historical = "source unavailable", true
		return st, 0, 1
	}
	if st.epoch == "" {
		st.epoch, st.offset, st.tail, st.err = p.Epoch, p.Tail, p.Tail, ""
		return st, 0, 0
	}
	if p.Epoch != st.epoch {
		// Only the previously observed unsent suffix is countable. Events
		// appended after the last snapshot are unknowable across restart.
		st.continuity++
		st.lost += st.tail - st.offset
		st.epoch, st.offset, st.historical = p.Epoch, 0, true
		st.err = "source restarted; continuity unknown"
	} else {
		st.err = ""
	}
	st.tail = p.Tail
	if p.Floor > st.offset+1 {
		st.lost += p.Floor - st.offset - 1
		st.offset, st.historical = p.Floor-1, true
	}
	conn := &syslogConn{network: target.network, addr: target.addr}
	defer conn.close()
	sent := 0
	for _, record := range p.Records {
		payload, err := m.formatSourceEvent(record.Event, format, source, p.Epoch, record.Offset)
		if err != nil {
			st.lost++
			st.offset, st.historical = record.Offset, true
			st.err = "event serialization failed"
			continue
		}
		if err := conn.send(ctx, payload); err != nil {
			st.err, st.historical = "destination send failed", true
			return st, sent, 1
		}
		st.offset = record.Offset
		st.lastSent = time.Now().UTC()
		sent++
	}
	return st, sent, 0
}

var _ evidence.ForwardReporter = (*SyslogManager)(nil)

// ForwardStatus reports sanitized current errors and sticky loss/history.
func (m *SyslogManager) ForwardStatus() []evidence.ForwardStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []evidence.ForwardStatus{}
	for _, target := range syslogTargets(m.config.Forwarders) {
		for _, source := range []evidence.Source{evidence.SourceEngine, evidence.SourceServices} {
			st, ok := m.progress[target.id][source]
			if !ok {
				continue
			}
			state := evidence.StateOK
			if st.historical || st.lost > 0 {
				state = evidence.StateRecovered
			}
			if st.err != "" {
				state = evidence.StateDegraded
			}
			out = append(out, evidence.ForwardStatus{
				Destination: target.id, Source: source, State: state,
				SentThrough: strconv.FormatUint(st.offset, 10), Backlog: st.tail - st.offset,
				Lost: st.lost, LastError: st.err, LastSuccessAt: optionalTime(st.lastSent),
			})
		}
		if m.auditLog != nil {
			st, ok := m.auditForwarders[target.id]
			state := evidence.StateOK
			if st.historical {
				state = evidence.StateRecovered
			}
			if !ok {
				state = evidence.StateUnknown
			}
			if st.lastError != "" {
				state = evidence.StateDegraded
			}
			out = append(out, evidence.ForwardStatus{Destination: target.id, Source: evidence.SourceAudit,
				State: state, SentThrough: fmt.Sprint(st.lastID), Backlog: uint64(max(0, st.backlog)),
				LastError: sanitizedAuditError(st.lastError), LastSuccessAt: optionalTime(st.lastSent)})
		}
	}
	return out
}

func sanitizedAuditError(err string) string {
	if err != "" {
		return "audit forwarding unavailable"
	}
	return ""
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// eventStatus provides append-epoch and historical counters alongside the
// stable evidence reporter. Callers hold mu.
func (m *SyslogManager) eventStatus() []map[string]any {
	out := []map[string]any{}
	for _, target := range syslogTargets(m.config.Forwarders) {
		for _, source := range []evidence.Source{evidence.SourceEngine, evidence.SourceServices} {
			st, ok := m.progress[target.id][source]
			if !ok {
				continue
			}
			out = append(out, map[string]any{
				"destination": target.id, "source": source, "epoch": st.epoch,
				"offset": strconv.FormatUint(st.offset, 10), "backlog": st.tail - st.offset,
				"sent": st.sent, "failed": st.failed, "lost": st.lost,
				"continuity_unknown": st.continuity, "last_error": st.err,
				"last_success": formatTime(st.lastSent),
			})
		}
	}
	return out
}
