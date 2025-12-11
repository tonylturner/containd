package flow

import (
	"net"
	"time"
	"strconv"
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
func (k Key) Hash() string {
	return k.SrcIP.String() + "|" + k.DstIP.String() + "|" +
		uint16ToStr(k.SrcPort) + "|" + uint16ToStr(k.DstPort) + "|" +
		uint8ToStr(k.Proto) + "|" + uint8ToStr(uint8(k.Dir))
}

func uint16ToStr(v uint16) string { return strconv.FormatUint(uint64(v), 10) }
func uint8ToStr(v uint8) string   { return strconv.FormatUint(uint64(v), 10) }

// State holds runtime flow state and timestamps.
type State struct {
	Key           Key
	FirstSeen     time.Time
	LastSeen      time.Time
	Bytes         uint64
	Packets       uint64
	Application   string
	TCPState      string
	IdleTimeout   time.Duration
	HardTimeout   time.Duration
	LastAction    string
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
