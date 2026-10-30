// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestCandidatesOrder(t *testing.T) {
	src, dst, anyDecoder := &mockDecoder{}, &mockDecoder{}, &mockDecoder{}
	for _, tc := range []struct {
		name     string
		proto    uint8
		sport    uint16
		dport    uint16
		fallback bool
		want     []Decoder
	}{
		{"source", 6, 502, 10000, false, []Decoder{src}},
		{"destination", 6, 10000, 80, false, []Decoder{dst, src}},
		{"both", 6, 502, 80, false, []Decoder{src, dst, src}},
		{"same-port", 6, 80, 80, false, []Decoder{dst, src}},
		{"source-fallback", 6, 502, 10000, true, []Decoder{src, anyDecoder}},
		{"destination-fallback", 6, 10000, 80, true, []Decoder{dst, src, anyDecoder}},
		{"both-fallback", 6, 502, 80, true, []Decoder{src, dst, src, anyDecoder}},
		{"fallback-only", 6, 10000, 10001, true, []Decoder{anyDecoder}},
		{"none", 6, 10000, 10001, false, nil},
		{"udp", 17, 502, 80, false, []Decoder{dst}},
		{"other-protocol", 1, 502, 80, true, []Decoder{anyDecoder}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager()
			m.tcpByPort[502], m.tcpByPort[80] = []Decoder{src}, []Decoder{dst, src}
			m.udpByPort[80] = []Decoder{dst}
			if tc.fallback {
				m.anyDecoders = []Decoder{anyDecoder}
			}
			state := &flow.State{Key: flow.Key{SrcPort: tc.sport, DstPort: tc.dport, Proto: tc.proto}}
			if got := m.candidates(state); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidates = %v, want %v", got, tc.want)
			}
			// Combining candidate lists must not append into the registry.
			if len(m.tcpByPort[502]) != 1 || len(m.tcpByPort[80]) != 2 {
				t.Fatal("candidate lookup changed the registry")
			}
		})
	}
}

func TestCandidatesSingleRegistryNoAlloc(t *testing.T) {
	m := NewManager()
	m.tcpByPort[502] = []Decoder{&mockDecoder{}, &mockDecoder{}}
	state := &flow.State{Key: flow.Key{SrcPort: 12345, DstPort: 502, Proto: 6}}
	if n := testing.AllocsPerRun(100, func() {
		if len(m.candidates(state)) != 2 {
			panic("missing candidates")
		}
	}); n != 0 {
		t.Fatalf("candidate lookup allocated %g times", n)
	}
}
