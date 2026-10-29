// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

type TransportConnectionID string

// ConnectionSlot is copyable with a State snapshot; the shared atomic slot
// keeps concurrent metadata readers safe. Initialize states with NewState.
type ConnectionSlot struct{ pointer *atomic.Pointer[Connection] }

func newConnectionSlot() ConnectionSlot {
	return ConnectionSlot{pointer: &atomic.Pointer[Connection]{}}
}
func (s ConnectionSlot) Load() *Connection {
	if s.pointer == nil {
		return nil
	}
	return s.pointer.Load()
}
func (s *ConnectionSlot) Store(c *Connection) {
	// Zero-value states are useful to standalone decoders before sharing.
	if s.pointer == nil {
		*s = newConnectionSlot()
	}
	s.pointer.Store(c)
}

// Connection is shared correlation evidence, never policy/reset coordinates.
// ID, Key, Status and Evidence are immutable after construction. An issued ID
// freezes assignment; an ID-less history may still acquire verified evidence.
type Connection struct {
	ID        TransportConnectionID
	Key       string // private incarnation identity, including offline capture
	Status    string
	Evidence  *conntrack.Evidence
	lifecycle atomic.Pointer[connectionLifecycle]
}

type connectionLifecycle struct {
	published, coverage, closed, unavailableReported atomic.Bool
	recoveryUntil                                    atomic.Int64
	fin                                              atomic.Uint32
}

func (c *Connection) mutable() *connectionLifecycle {
	if state := c.lifecycle.Load(); state != nil {
		return state
	}
	c.lifecycle.CompareAndSwap(nil, &connectionLifecycle{})
	return c.lifecycle.Load()
}

// InheritLifecycle retains pending-transaction coverage and close state when
// replacing an immutable authority snapshot of the same published identity.
func (c *Connection) InheritLifecycle(previous *Connection) {
	c.lifecycle.Store(previous.mutable())
}

func (c *Connection) Published() *atomic.Bool { return &c.mutable().published }
func (c *Connection) Coverage() *atomic.Bool  { return &c.mutable().coverage }
func (c *Connection) Closed() *atomic.Bool    { return &c.mutable().closed }
func (c *Connection) FIN() *atomic.Uint32     { return &c.mutable().fin }

// Verified is the immutable evidence snapshot selected at packet admission.
// Authority refreshes cannot change a packet halfway through its event pipeline.
func (c *Connection) Verified() bool { return c != nil && c.Evidence != nil && c.Status == "resolved" }

func (c *Connection) PublicID() TransportConnectionID {
	if c == nil {
		return ""
	}
	return c.ID
}
func (c *Connection) ResolutionStatus() string {
	if c == nil {
		return "wire"
	}
	return c.Status
}

func (c *Connection) LoseCorrelation(at time.Time, timeout time.Duration) {
	if at.IsZero() {
		at = time.Now()
	}
	until := at.Add(timeout).UnixNano()
	slot := &c.mutable().recoveryUntil
	for old := slot.Load(); old < until; old = slot.Load() {
		if slot.CompareAndSwap(old, until) {
			break
		}
	}
}
func (c *Connection) CorrelationAvailable(at time.Time) bool {
	return c.Coverage().Load() && c.CorrelationRecoveryElapsed(at)
}

// CorrelationRecoveryElapsed reports whether the latest loss window has ended,
// independently of SYN coverage. Unbound histories may be retired only then.
func (c *Connection) CorrelationRecoveryElapsed(at time.Time) bool {
	if at.IsZero() {
		at = time.Now()
	}
	return at.UnixNano() >= c.mutable().recoveryUntil.Load()
}
func (c *Connection) ReportUnavailable() bool {
	return c.mutable().unavailableReported.CompareAndSwap(false, true)
}

// MergeHistory preserves loss and notification history when verified evidence
// joins wire-only directions which had not issued their own public IDs.
func (c *Connection) MergeHistory(previous *Connection) {
	if previous.mutable().unavailableReported.Load() {
		c.mutable().unavailableReported.Store(true)
	}
	if previous.Coverage().Load() {
		c.Coverage().Store(true)
	}
	slot := &c.mutable().recoveryUntil
	until := previous.mutable().recoveryUntil.Load()
	for old := slot.Load(); old < until; old = slot.Load() {
		if slot.CompareAndSwap(old, until) {
			break
		}
	}
}

func (k Key) Tuple() conntrack.Tuple {
	s, sok := netip.AddrFromSlice(k.SrcIP)
	d, dok := netip.AddrFromSlice(k.DstIP)
	if !sok || !dok {
		return conntrack.Tuple{}
	}
	s, d = s.Unmap(), d.Unmap()
	family := uint8(2)
	if s.Is6() {
		family = 10
	}
	return conntrack.Tuple{Family: family, Protocol: k.Proto,
		Source: netip.AddrPortFrom(s, k.SrcPort), Destination: netip.AddrPortFrom(d, k.DstPort)}
}

func TupleKey(t conntrack.Tuple, dir Direction) Key {
	return Key{SrcIP: net.IP(t.Source.Addr().AsSlice()), DstIP: net.IP(t.Destination.Addr().AsSlice()),
		SrcPort: t.Source.Port(), DstPort: t.Destination.Port(), Proto: t.Protocol, Dir: dir}
}

func (c *Connection) Direction(k Key) Direction {
	if c != nil && c.Evidence != nil && k.Tuple() == c.Evidence.Reply {
		return DirReverse
	}
	if c != nil && c.Evidence != nil && k.Tuple() == c.Evidence.Original {
		return DirForward
	}
	return k.Dir
}

func (c *Connection) Peer(k Key) Key {
	if !c.Verified() {
		return k.Reversed()
	}
	if c.Direction(k) == DirForward {
		return TupleKey(c.Evidence.Reply, DirReverse)
	}
	return TupleKey(c.Evidence.Original, DirForward)
}

// LogicalIPs returns event-direction client/backend coordinates for consumers
// that explicitly support them. Wire endpoints and FlowID are not rewritten.
func (c *Connection) LogicalIPs(k Key) (string, string, bool) {
	if !c.Verified() || k.Tuple() != c.Evidence.Original && k.Tuple() != c.Evidence.Reply {
		return "", "", false
	}
	client, backend := c.Evidence.Original.Source.Addr().String(), c.Evidence.Reply.Source.Addr().String()
	if c.Direction(k) == DirReverse {
		return backend, client, true
	}
	return client, backend, true
}
