// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func (e *Engine) legacyTransportEligible(pkt capture.Packet) bool {
	if pkt.Invalid != "" || pkt.Proto != 6 && pkt.Proto != 17 {
		return false
	}
	state := &flow.State{Key: packetKey(pkt)}
	if dir, known := icsServiceDirection(pkt); known {
		state.Key.Dir = dir
	}
	parsed := &dpi.ParsedPacket{Proto: pkt.Transport, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	if !e.ShouldInspect(state, parsed) {
		return false
	}
	if ics.IsDecoderPortOn(pkt.Proto, pkt.SrcPort) || ics.IsDecoderPortOn(pkt.Proto, pkt.DstPort) {
		return true
	}
	if snap := e.ruleSnap.Load(); snap != nil {
		for _, entry := range snap.Firewall {
			if shouldInspectFirewallEntry(entry, state, parsed) {
				return true
			}
		}
	}
	return false
}

// Overflow telemetry has no decoded payload. Use only port/handshake hints
// and already-admitted evidence, preserving the observed wire coordinates.
func transportOverflowIdentity(pkt capture.Packet, c *flow.Connection) (flow.Key, string) {
	key := packetKey(pkt)
	if dir, known := icsServiceDirection(pkt); known {
		key.Dir = dir
	}
	if dir, known := handshakeDirection(pkt); known {
		key.Dir = dir
	}
	if c != nil {
		key.Dir = c.Direction(key)
	}
	for _, port := range ics.DecoderPorts() {
		if port.Transport == pkt.Proto && (port.Port == pkt.SrcPort || port.Port == pkt.DstPort) {
			return key, port.Protocol
		}
	}
	return key, pkt.Transport
}

// The loss index is independent of lookup TTLs: a quiet live connection still
// needs a tuple-scoped loss marker. Placeholders retain loss while its opener
// is queued. Closed incarnations are reclaimed, never live ones. The flow
// sweep separately reclaims expired, unbound histories with no queued owners.
func (r *transportResolver) admissionHistoryLocked(tuple conntrack.Tuple) *transportAdmission {
	if entry := r.indexed[tuple]; entry != nil {
		if !entry.connection.Closed().Load() {
			return entry
		}
		delete(r.indexed, tuple)
	}
	if len(r.indexed) >= transportAliasLimit {
		return nil
	}
	entry := &transportAdmission{connection: &flow.Connection{}}
	r.indexed[tuple] = entry
	return entry
}

// Sweep only on the existing flow-sweep cadence, not on admission/capacity
// checks. A queued or in-flight packet still owns its token even after the
// recovery timeout; it may later bind the history to a live incarnation.
func (r *transportResolver) sweepAdmission(now time.Time) {
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	for tuple, entry := range r.indexed {
		if entry.connection.Key == "" && entry.queued == 0 &&
			entry.connection.CorrelationRecoveryElapsed(now) {
			delete(r.indexed, tuple)
			r.authority.count("coverage_index_reclaimed")
		}
	}
}

func (r *transportResolver) releaseAdmission(p transportPacket) {
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	r.releaseAdmissionLocked(p)
}

func (r *transportResolver) releaseAdmissionLocked(p transportPacket) {
	if p.history != nil {
		p.history.queued--
	}
	r.bytes.Add(-int64(len(p.packet.Payload)))
	r.count.Add(-1)
}

// Connection close/expiry knows its aliases, so reclamation is indexed rather
// than a full-table scan on capture admission. Never retire a newer SYN's slot.
func (r *transportResolver) retireAdmission(state *flow.State) {
	c := state.Connection.Load()
	tuples := []conntrack.Tuple{state.Key.Tuple(), state.Key.Reversed().Tuple()}
	if c.Evidence != nil {
		tuples = append(tuples, c.Evidence.Original, c.Evidence.Reply)
	}
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	for _, tuple := range tuples {
		if entry := r.indexed[tuple]; entry != nil && entry.connection.Key == c.Key {
			delete(r.indexed, tuple)
		}
	}
}

func (r *transportResolver) admitHistoryLocked(pkt capture.Packet) *transportAdmission {
	tuple := packetKey(pkt).Tuple()
	entry := r.admissionHistoryLocked(tuple)
	if entry == nil {
		return nil
	}
	if pkt.Proto == 6 && pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0 && pkt.TCP.Flags&capture.TCPFlagACK == 0 {
		if !entry.hasSYN || entry.synSeq != pkt.TCP.Seq {
			entry = &transportAdmission{connection: &flow.Connection{}, synSeq: pkt.TCP.Seq, hasSYN: true}
			r.indexed[tuple] = entry
		}
	}
	return entry
}

func (r *transportResolver) trackConnection(state *flow.State, at time.Time, history *transportAdmission) {
	c := state.Connection.Load()
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	observed := state.Key.Tuple()
	if history != nil && r.indexed[observed] != history {
		// A later admitted SYN already owns this tuple. Older queued packets
		// must neither steal its slot nor copy its losses into the predecessor.
		return
	}
	tuples := []conntrack.Tuple{observed}
	if c.Evidence != nil {
		tuples = append(tuples, c.Evidence.Original, c.Evidence.Reply)
	}
	for _, tuple := range tuples {
		entry := r.indexed[tuple]
		if entry != nil && !entry.connection.Closed().Load() {
			if entry != history && entry.hasSYN && entry.connection.Key == "" {
				continue // An opener queued on the other tuple owns its placeholder.
			}
			if entry.connection.Key == "" && c.Coverage().Load() {
				// Admission has just regained a slot for an already-started
				// history. Its preceding unindexed interval may contain loss.
				c.LoseCorrelation(at, anomaly.ModbusPairingTimeout)
			}
			if entry.connection.Key == "" || entry.connection.Key == c.Key {
				c.MergeHistory(entry.connection)
			}
			entry.connection = c
			continue
		}
		if c.Coverage().Load() {
			// No index existed during the preceding interval. Do not assume
			// that an unrecorded drop there was harmless.
			c.LoseCorrelation(at, anomaly.ModbusPairingTimeout)
		}
		entry = r.admissionHistoryLocked(tuple)
		if entry == nil {
			c.LoseCorrelation(at, anomaly.ModbusPairingTimeout)
			r.authority.count("coverage_capacity")
			continue
		}
		entry.connection = c
	}
}

// Discovery widens only passive identity admission, not decoder selection.
func (e *Engine) transportEligible(pkt capture.Packet) bool {
	if e.legacyTransportEligible(pkt) {
		return true
	}
	if pkt.Invalid != "" || pkt.Proto != 6 && pkt.Proto != 17 || e.observation == nil {
		return false
	}
	state := &flow.State{Key: packetKey(pkt)}
	if !e.dpiInspectionEnabled(state) {
		return false
	}
	if r := e.transport; r != nil {
		r.admissionMu.Lock()
		entry := r.indexed[state.Key.Tuple()]
		settled := entry != nil && entry.settled && entry.queued == 0
		if settled && entry.coverage != nil && entry.coverage.root().lost {
			// Loss notices and subsequent packets must keep the worker's
			// ordering, even after discovery has reached a terminal result.
			settled = false
		}
		if settled && pkt.TCP.Valid && isSYN(pkt.TCP.Flags) && (!entry.hasSYN || entry.synSeq != pkt.TCP.Seq) {
			settled = false
		}
		r.admissionMu.Unlock()
		if settled {
			return false
		}
	}
	return true
}

func (r *transportResolver) settleObservation(st *flow.State) {
	c := st.Connection.Load()
	if c == nil {
		return
	}
	tuples := []conntrack.Tuple{st.Key.Tuple(), st.Key.Reversed().Tuple()}
	if c.Evidence != nil {
		tuples = append(tuples, c.Evidence.Original, c.Evidence.Reply)
	}
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	for _, tuple := range tuples {
		if entry := r.indexed[tuple]; entry != nil && entry.connection.Key == c.Key {
			entry.settled = true
		}
	}
}
