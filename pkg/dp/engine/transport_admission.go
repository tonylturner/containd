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

func (e *Engine) transportEligible(pkt capture.Packet) bool {
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
// is queued. Closed incarnations are reclaimed, never live ones.
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
