// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// Seeds returns owned nonempty transport payloads in capture/delivery order,
// including duplicates. It does not strip any protocol layer.
func Seeds(f Fixture) [][]byte {
	var out [][]byte
	for _, p := range f.Packets {
		if len(p.Decoded.Payload) > 0 {
			out = append(out, append([]byte(nil), p.Decoded.Payload...))
		}
	}
	return out
}

// StreamSeeds is intentionally stricter than Manager replay: only explicitly
// contiguous pristine TCP fixtures with sequence anchors, no gaps, overlaps or
// retransmits are accepted. It concatenates per-direction bytes for parser
// fuzzing, never for Replay. UDP and transformed fixtures are rejected.
func StreamSeeds(f Fixture) ([][]byte, error) {
	if !f.Spec.Contiguous || len(f.Derived) > 0 {
		return nil, fmt.Errorf("stream seeds require declared pristine contiguous fixture")
	}
	type stream struct {
		bytes []byte
		next  uint32
	}
	streams := map[string]*stream{}
	var order []string
	for _, p := range f.Packets {
		if p.Decoded.Transport != "tcp" || !p.Decoded.TCP.Valid || !p.HasOrigin {
			return nil, fmt.Errorf("stream seed requires anchored TCP")
		}
		if len(p.Decoded.Payload) == 0 {
			continue
		}
		key := fmt.Sprintf("%s/%d", p.Connection, p.Dir)
		s := streams[key]
		if s == nil {
			s = &stream{next: p.Origin}
			streams[key] = s
			order = append(order, key)
		}
		seq := p.Decoded.TCP.Seq
		if p.Decoded.TCP.Flags&capture.TCPFlagSYN != 0 {
			seq++
		}
		if seq != s.next || len(s.bytes)+len(p.Decoded.Payload) > MaxCaptureBytes {
			return nil, fmt.Errorf("noncontiguous or oversized stream seed")
		}
		s.bytes = append(s.bytes, p.Decoded.Payload...)
		s.next += uint32(len(p.Decoded.Payload))
	}
	var out [][]byte
	for _, key := range order {
		out = append(out, streams[key].bytes)
	}
	return out, nil
}
