// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

const MaxTransformPackets = 200000
const MaxTransformPayload = 32768

type Transform interface {
	Apply(Fixture) (Fixture, error)
}
type transform struct {
	name string
	run  func([]Packet) ([]Packet, error)
}

func (t transform) Apply(f Fixture) (Fixture, error) {
	if len(f.Packets) == 0 || len(f.Packets) > MaxTransformPackets {
		return Fixture{}, fmt.Errorf("transform input packet bound")
	}
	for _, p := range f.Packets {
		if p.Connection == "" || (p.Dir != dpi.ClientToServer && p.Dir != dpi.ServerToClient) {
			return Fixture{}, fmt.Errorf("transform requires connection identity and direction")
		}
		n := 0
		for _, span := range p.Source {
			if span.Capture == "" || span.Frame <= 0 || span.Start < 0 || span.End < span.Start {
				return Fixture{}, fmt.Errorf("invalid source span")
			}
			n += span.End - span.Start
		}
		if n != len(p.Decoded.Payload) || len(p.Source) == 0 {
			return Fixture{}, fmt.Errorf("source span length mismatch")
		}
		if p.Decoded.Transport != "tcp" || !p.Decoded.TCP.Valid {
			return Fixture{}, fmt.Errorf("%s requires TCP with valid sequence metadata", t.name)
		}
	}
	packets := make([]Packet, len(f.Packets))
	for i, p := range f.Packets {
		packets[i] = clonePacket(p)
	}
	out, err := t.run(packets)
	if err != nil {
		return Fixture{}, err
	}
	if len(out) > MaxTransformPackets {
		return Fixture{}, fmt.Errorf("transform packet bound")
	}
	// Generated delivery times are deterministic and monotonic, not capture time.
	start := time.Unix(0, 0).UTC()
	if len(f.Packets) > 0 {
		start = f.Packets[0].Time
	}
	for i := range out {
		out[i].Wire = nil
		out[i].Time = start.Add(time.Duration(i) * time.Microsecond)
		out[i].Decoded.Timestamp = out[i].Time
	}
	f.Packets = out
	f.Derived = append(append([]string(nil), f.Derived...), t.name)
	return f, nil
}
func clonePacket(p Packet) Packet {
	p.Source = append([]SourceSpan(nil), p.Source...)
	p.Wire = append([]byte(nil), p.Wire...)
	p.Decoded.Payload = append([]byte(nil), p.Decoded.Payload...)
	p.Decoded.SrcIP = append([]byte(nil), p.Decoded.SrcIP...)
	p.Decoded.DstIP = append([]byte(nil), p.Decoded.DstIP...)
	return p
}
func control(p Packet) bool {
	return len(p.Decoded.Payload) == 0 || p.Decoded.TCP.Flags & ^(capture.TCPFlagACK|capture.TCPFlagPSH) != 0
}
func sameDirection(a, b Packet) bool {
	return a.Connection == b.Connection && a.Dir == b.Dir && a.Decoded.SrcIP.Equal(b.Decoded.SrcIP) && a.Decoded.DstIP.Equal(b.Decoded.DstIP) && a.Decoded.SrcPort == b.Decoded.SrcPort && a.Decoded.DstPort == b.Decoded.DstPort
}
func subspans(spans []SourceSpan, start, end int) []SourceSpan {
	var out []SourceSpan
	pos := 0
	for _, s := range spans {
		n := s.End - s.Start
		lo, hi := max(start, pos), min(end, pos+n)
		if lo < hi {
			out = append(out, SourceSpan{s.Capture, s.Frame, s.Start + lo - pos, s.Start + hi - pos})
		}
		pos += n
	}
	return out
}

// Split partitions ordinary data packets, preserving sequence mapping and PSH
// only on the final piece. SYN/FIN/RST and other control packets are barriers.
func Split(maxPayload int) Transform {
	return transform{fmt.Sprintf("split(%d)", maxPayload), func(in []Packet) ([]Packet, error) {
		if maxPayload <= 0 || maxPayload > MaxTransformPayload {
			return nil, fmt.Errorf("invalid split bound")
		}
		var out []Packet
		for _, p := range in {
			if control(p) {
				out = append(out, p)
				continue
			}
			for start := 0; start < len(p.Decoded.Payload); start += maxPayload {
				if len(out) >= MaxTransformPackets {
					return nil, fmt.Errorf("split packet bound")
				}
				end := min(start+maxPayload, len(p.Decoded.Payload))
				piece := packetRange(p, start, end)
				out = append(out, piece)
			}
		}
		return out, nil
	}}
}

func packetRange(p Packet, start, end int) Packet {
	piece := clonePacket(p)
	piece.Decoded.Payload = append([]byte(nil), p.Decoded.Payload[start:end]...)
	piece.Decoded.TCP.Seq += uint32(start)
	piece.Source = subspans(p.Source, start, end)
	if end < len(p.Decoded.Payload) {
		piece.Decoded.TCP.Flags &^= capture.TCPFlagPSH
	}
	return piece
}

// EveryCuts returns one derivative per possible two-part cut of each ordinary
// TCP payload, in packet/cut order. It fails rather than silently sampling when
// maxVariants, 128 MiB of retained payloads, or 200000 total records is exceeded.
func EveryCuts(f Fixture, maxVariants int) ([]Fixture, error) {
	count, bytes := 0, 0
	for _, p := range f.Packets {
		bytes += len(p.Decoded.Payload)
		if !control(p) {
			count += len(p.Decoded.Payload) - 1
		}
	}
	if maxVariants <= 0 || count > maxVariants || int64(count)*int64(bytes) > 128<<20 || int64(count)*int64(len(f.Packets)+1) > MaxTransformPackets {
		return nil, fmt.Errorf("cut enumeration exceeds budget")
	}
	// Validate even when a fixture has no eligible cuts (notably UDP).
	if _, err := (transform{"validate", func(in []Packet) ([]Packet, error) { return in, nil }}).Apply(f); err != nil {
		return nil, err
	}
	var out []Fixture
	for index, p := range f.Packets {
		if control(p) {
			continue
		}
		for cut := 1; cut < len(p.Decoded.Payload); cut++ {
			tr := transform{fmt.Sprintf("cut(%d,%d)", index, cut), func(in []Packet) ([]Packet, error) {
				packets := make([]Packet, 0, len(in)+1)
				packets = append(packets, in[:index]...)
				packets = append(packets, packetRange(in[index], 0, cut), packetRange(in[index], cut, len(in[index].Decoded.Payload)))
				packets = append(packets, in[index+1:]...)
				return packets, nil
			}}
			variant, err := tr.Apply(f)
			if err != nil {
				return nil, err
			}
			out = append(out, variant)
		}
	}
	return out, nil
}

// Coalesce combines only adjacent, contiguous packets with the same direction,
// ACK and window. Opposite directions, controls, gaps and overlaps are barriers.
func Coalesce(maxPayload int) Transform {
	return transform{fmt.Sprintf("coalesce(%d)", maxPayload), func(in []Packet) ([]Packet, error) {
		if maxPayload <= 0 || maxPayload > MaxTransformPayload {
			return nil, fmt.Errorf("invalid coalesce bound")
		}
		var out []Packet
		for _, p := range in {
			if len(out) > 0 {
				prev := &out[len(out)-1]
				if !control(*prev) && !control(p) && sameDirection(*prev, p) && prev.Decoded.TCP.Ack == p.Decoded.TCP.Ack && prev.Decoded.TCP.Window == p.Decoded.TCP.Window && prev.Decoded.TCP.Seq+uint32(len(prev.Decoded.Payload)) == p.Decoded.TCP.Seq && len(prev.Decoded.Payload)+len(p.Decoded.Payload) <= maxPayload {
					prev.Decoded.Payload = append(prev.Decoded.Payload, p.Decoded.Payload...)
					prev.Source = append(prev.Source, p.Source...)
					prev.Decoded.TCP.Flags = p.Decoded.TCP.Flags
					continue
				}
			}
			out = append(out, p)
		}
		return out, nil
	}}
}

// Reorder permutes each full window of consecutive ordinary packets in one
// direction. Incomplete windows and all causal/control barriers stay in place.
// The explicit permutation is a bijection of [0,window), window <= 32.
func Reorder(window int, permutation []int) Transform {
	perm := append([]int(nil), permutation...)
	return transform{fmt.Sprintf("reorder(%d,%v)", window, perm), func(in []Packet) ([]Packet, error) {
		if window < 2 || window > 32 || len(perm) != window {
			return nil, fmt.Errorf("invalid reorder window")
		}
		seen := map[int]bool{}
		for _, i := range perm {
			if i < 0 || i >= window || seen[i] {
				return nil, fmt.Errorf("invalid permutation")
			}
			seen[i] = true
		}
		out := make([]Packet, 0, len(in))
		for start := 0; start < len(in); {
			end := start + 1
			if !control(in[start]) {
				for end < len(in) && !control(in[end]) && sameDirection(in[start], in[end]) {
					end++
				}
			}
			for start+window <= end {
				bytes := 0
				for _, p := range in[start : start+window] {
					bytes += len(p.Decoded.Payload)
				}
				if bytes > MaxTransformPayload {
					return nil, fmt.Errorf("reorder payload budget")
				}
				for _, i := range perm {
					out = append(out, in[start+i])
				}
				start += window
			}
			out = append(out, in[start:end]...)
			start = end
		}
		return out, nil
	}}
}

// Retransmit inserts an exact owned duplicate immediately after each selected
// ordinary data arrival. Indices address this transform's input, not originals.
func Retransmit(packetIndices []int) Transform {
	indices := append([]int(nil), packetIndices...)
	return transform{fmt.Sprintf("retransmit(%v)", indices), func(in []Packet) ([]Packet, error) {
		selected := map[int]bool{}
		for _, i := range indices {
			if i < 0 || i >= len(in) || selected[i] || control(in[i]) {
				return nil, fmt.Errorf("invalid retransmit index %d", i)
			}
			selected[i] = true
		}
		var out []Packet
		for i, p := range in {
			out = append(out, p)
			if selected[i] {
				out = append(out, clonePacket(p))
			}
		}
		return out, nil
	}}
}
func Apply(f Fixture, transforms ...Transform) (Fixture, error) {
	var err error
	for _, t := range transforms {
		if t == nil {
			return Fixture{}, fmt.Errorf("nil transform")
		}
		f, err = t.Apply(f)
		if err != nil {
			return Fixture{}, err
		}
	}
	return f, nil
}
