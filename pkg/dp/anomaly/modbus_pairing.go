// SPDX-License-Identifier: Apache-2.0

package anomaly

import (
	"fmt"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	maxPendingConnections   = 4096
	maxPendingPerConnection = 256
	pendingTTL              = 2 * time.Minute
)

type transactionKey struct {
	direction flow.Direction
	id        uint16
	unit      uint8
	hasUnit   bool
}

type pendingConnection struct {
	transactions map[transactionKey]time.Time
	connection   *flow.Connection
	last         time.Time
	incomplete   bool
}

type PairingStats struct {
	Matched             uint64 `json:"matched"`
	Unmatched           uint64 `json:"unmatched"`
	Unavailable         uint64 `json:"unavailable"`
	Capacity            uint64 `json:"capacity"`
	Expired             uint64 `json:"expired"`
	PendingConnections  int    `json:"pendingConnections"`
	PendingTransactions int    `json:"pendingTransactions"`
}

func (d *Detector) PairingStats() PairingStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.pairing
	out.PendingConnections = len(d.pendingTxns)
	for _, c := range d.pendingTxns {
		out.PendingTransactions += len(c.transactions)
	}
	return out
}

func (d *Detector) ForgetConnection(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.pendingTxns {
		if key == id || strings.HasPrefix(key, id+"/wire/") {
			delete(d.pendingTxns, key)
		}
	}
}

func pairingIdentity(ev dpi.Event) (id string, direction flow.Direction, available bool, status string) {
	key, ok := flow.ParseKey(ev.FlowID)
	if !ok {
		return "", 0, false, "wire_identity_missing"
	}
	direction = key.Dir
	canonical := key
	if canonical.Dir == flow.DirReverse {
		canonical = canonical.Reversed()
	}
	if c := ev.Connection; c != nil {
		if c.Verified() {
			if key.Tuple() != c.Evidence.Original && key.Tuple() != c.Evidence.Reply {
				return "", 0, false, "tuple_mismatch"
			}
			available := c.Coverage().Load() && !c.Gap().Load()
			status = "capture_incomplete"
			if available {
				status = "resolved"
			}
			return c.Key, c.Direction(key), available, status
		}
		status = c.ResolutionStatus()
		if status == "offline" && c.Gap().Load() {
			status = "capture_incomplete"
		}
		return c.Key + "/wire/" + canonical.Hash(), direction, status == "offline", status
	}
	// Standalone decoder/PCAP consumers have no live CT authority. Their
	// explicit full wire key is usable; an IP pair is never a fallback key.
	return canonical.Hash(), direction, true, "offline"
}

func (d *Detector) sweepPending(now time.Time) {
	if !d.lastPendingSweep.IsZero() && now.Sub(d.lastPendingSweep) < time.Second {
		return
	}
	d.lastPendingSweep = now
	for id, c := range d.pendingTxns {
		for key, at := range c.transactions {
			if now.Sub(at) > pendingTTL {
				delete(c.transactions, key)
				c.incomplete = true
				if c.connection != nil {
					c.connection.Gap().Store(true)
				}
				d.pairing.Expired++
			}
		}
		if now.Sub(c.last) > 2*pendingTTL {
			delete(d.pendingTxns, id)
		}
	}
}

func (d *Detector) pairModbus(srcIP, dstIP string, ev dpi.Event, tid uint16, unit uint8, hasUnit bool) []Anomaly {
	reply := ev.Kind == "response" || ev.Kind == "exception" && isModbusExceptionReply(ev, srcIP, dstIP)
	if ev.Kind != "request" && !reply {
		return nil
	}
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	d.sweepPending(now)
	id, direction, available, status := pairingIdentity(ev)
	key := transactionKey{direction: direction, id: tid, unit: unit, hasUnit: hasUnit}
	c := d.pendingTxns[id]
	unavailable := func(reason string) []Anomaly {
		d.pairing.Unavailable++
		return []Anomaly{{Type: "correlation_unavailable", Protocol: "modbus", Severity: "low",
			Message: "Modbus transaction correlation unavailable", SourceIP: srcIP, DestIP: dstIP,
			Attributes: map[string]any{"correlation_status": reason, "transaction_id": tid, "unit_id": unit}, Timestamp: ev.Timestamp}}
	}
	if id == "" {
		return unavailable(status)
	}
	if ev.Kind == "request" {
		if c == nil {
			if len(d.pendingTxns) >= maxPendingConnections {
				if ev.Connection != nil {
					ev.Connection.Gap().Store(true)
				}
				d.pairing.Capacity++
				return unavailable("pending_capacity")
			}
			c = &pendingConnection{transactions: make(map[transactionKey]time.Time), connection: ev.Connection}
			d.pendingTxns[id] = c
		}
		c.last = now
		if _, exists := c.transactions[key]; !exists && len(c.transactions) >= maxPendingPerConnection {
			c.incomplete = true
			if c.connection != nil {
				c.connection.Gap().Store(true)
			}
			d.pairing.Capacity++
			return unavailable("pending_capacity")
		}
		c.transactions[key] = now
		return nil
	}
	if key.direction == flow.DirForward {
		key.direction = flow.DirReverse
	} else {
		key.direction = flow.DirForward
	}
	if c != nil {
		c.last = now
		if _, matched := c.transactions[key]; matched {
			delete(c.transactions, key)
			d.pairing.Matched++
			return nil
		}
		if c.incomplete {
			return unavailable("pending_incomplete")
		}
	}
	if !available || c == nil && len(d.pendingTxns) >= maxPendingConnections {
		return unavailable(status)
	}
	d.pairing.Unmatched++
	return []Anomaly{{Type: "protocol_violation", Protocol: "modbus", Severity: "medium",
		Message:  fmt.Sprintf("Modbus %s (txn %d) without prior request", ev.Kind, tid),
		SourceIP: srcIP, DestIP: dstIP, Attributes: map[string]any{"transaction_id": tid, "unit_id": unit},
		Timestamp: ev.Timestamp}}
}
