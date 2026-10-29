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
func (r *transportResolver) admissionHistoryLocked(tuple conntrack.Tuple) *flow.Connection {
	if c := r.indexed[tuple]; c != nil && !c.Closed().Load() {
		return c
	}
	if len(r.indexed) >= transportAliasLimit {
		for key, c := range r.indexed {
			if c.Closed().Load() {
				delete(r.indexed, key)
			}
		}
	}
	if len(r.indexed) >= transportAliasLimit {
		return nil
	}
	c := &flow.Connection{}
	r.indexed[tuple] = c
	return c
}

func (r *transportResolver) trackConnection(state *flow.State, at time.Time) {
	c := state.Connection.Load()
	r.admissionMu.Lock()
	defer r.admissionMu.Unlock()
	tuples := []conntrack.Tuple{state.Key.Tuple()}
	if c.Evidence != nil {
		tuples = append(tuples, c.Evidence.Original, c.Evidence.Reply)
	}
	for _, tuple := range tuples {
		previous := r.indexed[tuple]
		if previous != nil && !previous.Closed().Load() {
			if previous.Key == "" || previous.Key == c.Key {
				c.MergeHistory(previous)
			}
			r.indexed[tuple] = c
			continue
		}
		if c.Coverage().Load() {
			// No index existed during the preceding interval. Do not assume
			// that an unrecorded drop there was harmless.
			c.LoseCorrelation(at, anomaly.ModbusPairingTimeout)
		}
		if r.admissionHistoryLocked(tuple) == nil {
			c.LoseCorrelation(at, anomaly.ModbusPairingTimeout)
			r.authority.count("coverage_capacity")
			continue
		}
		r.indexed[tuple] = c
	}
}
