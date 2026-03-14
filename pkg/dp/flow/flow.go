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

type Direction uint8

const (
	DirForward Direction = iota
	DirReverse
)

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
