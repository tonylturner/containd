// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package flow

import (
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Key represents a 5-tuple flow key with direction.
type Key struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8 // IP protocol number
	Dir     Direction
}

// Direction tells which side of a connection sent the packets of a Key:
// DirForward from the side that opened the connection, DirReverse from
// the side that accepted it. SrcIP/DstIP are always the wire addresses.
type Direction uint8

const (
	DirForward Direction = iota
	DirReverse
)

// Reversed returns the key of the opposite direction of the same
// connection: endpoints swapped, direction flipped.
func (k Key) Reversed() Key {
	dir := DirReverse
	if k.Dir == DirReverse {
		dir = DirForward
	}
	return Key{
		SrcIP:   k.DstIP,
		DstIP:   k.SrcIP,
		SrcPort: k.DstPort,
		DstPort: k.SrcPort,
		Proto:   k.Proto,
		Dir:     dir,
	}
}

// OpenerIP returns the address of the side that opened the connection.
func (k Key) OpenerIP() net.IP {
	if k.Dir == DirReverse {
		return k.DstIP
	}
	return k.SrcIP
}

// ServerIP returns the address of the side that accepted the connection.
func (k Key) ServerIP() net.IP {
	if k.Dir == DirReverse {
		return k.SrcIP
	}
	return k.DstIP
}

// Hash returns the public directional flow ID. Its textual format is stable;
// internal tuple maps should use MapKey instead.
func (k Key) Hash() string {
	var buf [128]byte // two IPv6 addresses, ports, protocol and separators
	b := appendIP(buf[:0], k.SrcIP)
	b = append(b, '|')
	b = appendIP(b, k.DstIP)
	b = append(b, '|')
	b = strconv.AppendUint(b, uint64(k.SrcPort), 10)
	b = append(b, '|')
	b = strconv.AppendUint(b, uint64(k.DstPort), 10)
	b = append(b, '|', '0'+k.Proto/100%10, '0'+k.Proto/10%10, '0'+k.Proto%10, '|', '0'+byte(k.Dir))
	return string(b)
}

func appendIP(b []byte, ip net.IP) []byte {
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return addr.Unmap().AppendTo(b)
	}
	return append(b, ip.String()...)
}

// State holds runtime flow state and timestamps.
type State struct {
	Key          Key
	idKey        MapKey
	id           string
	Connection   ConnectionSlot   `json:"-"`
	InlinePolicy InlinePolicySlot `json:"-"`
	FirstSeen    time.Time
	LastSeen     time.Time
	Bytes        uint64
	Packets      uint64
	Application  string
	TCPState     string
	IdleTimeout  time.Duration
	HardTimeout  time.Duration
	LastAction   string
	// Tags are the labels of the TAG rules that match this connection
	// at evidence binding. The engine guards updates and snapshots with flowMu.
	Tags []string
	// CaptureHook is receive-time provenance retained in learner snapshots,
	// not inferred from correlation success or the current configuration.
	CaptureHook string `json:"-"`
}

func NewState(key Key, now time.Time) *State {
	var inline InlinePolicySlot
	inline.Store(nil)
	return &State{
		Key:          key,
		idKey:        key.MapKey(),
		id:           key.Hash(),
		Connection:   newConnectionSlot(),
		InlinePolicy: inline,
		FirstSeen:    now,
		LastSeen:     now,
	}
}

// ID returns the public flow ID without formatting the tuple again. The cache
// is immutable so State snapshots remain copyable. Standalone callers may
// construct states directly or edit Key (including its IP slices); those keys
// are formatted afresh rather than returning a stale ID.
func (s *State) ID() string {
	if s.id != "" && s.idKey == s.Key.MapKey() {
		return s.id
	}
	return s.Key.Hash()
}

// Touch updates timestamps and counters.
func (s *State) Touch(bytes uint64, now time.Time) {
	s.Packets++
	s.Bytes += bytes
	s.LastSeen = now
}

func (s *State) Expired(now time.Time) bool {
	if s.HardTimeout > 0 && now.Sub(s.FirstSeen) > s.HardTimeout {
		return true
	}
	if s.IdleTimeout > 0 && now.Sub(s.LastSeen) > s.IdleTimeout {
		return true
	}
	return false
}
