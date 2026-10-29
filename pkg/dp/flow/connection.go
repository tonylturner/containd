// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"net"
	"net/netip"
	"sync/atomic"

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
// ID, Key, Status and Evidence are immutable after construction. Publication
// freezes assignment; coverage may be lost without renaming public history.
type Connection struct {
	ID               TransportConnectionID
	Key              string // private incarnation identity, including offline capture
	Status           string
	Evidence         *conntrack.Evidence
	Authority        *atomic.Uint64
	AuthorityVersion uint64
	LossEpoch        uint64
	AuthorityLoss    uint64
	lifecycle        atomic.Pointer[connectionLifecycle]
	Unavailable      atomic.Pointer[string]
}

type connectionLifecycle struct {
	gap, published, coverage, closed atomic.Bool
	fin                              atomic.Uint32
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

func (c *Connection) Gap() *atomic.Bool       { return &c.mutable().gap }
func (c *Connection) Published() *atomic.Bool { return &c.mutable().published }
func (c *Connection) Coverage() *atomic.Bool  { return &c.mutable().coverage }
func (c *Connection) Closed() *atomic.Bool    { return &c.mutable().closed }
func (c *Connection) FIN() *atomic.Uint32     { return &c.mutable().fin }

func (c *Connection) Verified() bool {
	return c != nil && c.Evidence != nil && c.Unavailable.Load() == nil &&
		(c.Authority == nil || c.Authority.Load() == c.AuthorityVersion)
}

func (c *Connection) PublicID() TransportConnectionID {
	if c.Verified() {
		return c.ID
	}
	return ""
}

func (c *Connection) ResolutionStatus() string {
	if c == nil {
		return "offline"
	}
	if status := c.Unavailable.Load(); status != nil {
		return *status
	}
	if c.Evidence != nil && !c.Verified() {
		return "zone_unverified"
	}
	return c.Status
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
	if c.Verified() && k.Tuple() == c.Evidence.Reply {
		return DirReverse
	}
	if c.Verified() && k.Tuple() == c.Evidence.Original {
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
