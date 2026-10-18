// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package flow

import (
	"net"
	"strconv"
	"strings"
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

// Hash provides a simple string hash for map usage.
// Uses strings.Builder to minimize allocations on the hot path.
func (k Key) Hash() string {
	var b strings.Builder
	b.Grow(64) // pre-allocate typical size
	b.WriteString(k.SrcIP.String())
	b.WriteByte('|')
	b.WriteString(k.DstIP.String())
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(k.SrcPort), 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(k.DstPort), 10))
	b.WriteByte('|')
	b.WriteByte('0' + k.Proto/100%10)
	b.WriteByte('0' + k.Proto/10%10)
	b.WriteByte('0' + k.Proto%10)
	b.WriteByte('|')
	b.WriteByte('0' + byte(k.Dir))
	return b.String()
}

// State holds runtime flow state and timestamps.
type State struct {
	Key         Key
	FirstSeen   time.Time
	LastSeen    time.Time
	Bytes       uint64
	Packets     uint64
	Application string
	TCPState    string
	IdleTimeout time.Duration
	HardTimeout time.Duration
	LastAction  string
}

func NewState(key Key, now time.Time) *State {
	return &State{
		Key:       key,
		FirstSeen: now,
		LastSeen:  now,
	}
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
