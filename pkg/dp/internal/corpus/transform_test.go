// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestTransformEquivalenceAndOwnership(t *testing.T) {
	f := fixture(t, wire(6, ^uint32(0)-1, capture.TCPFlagSYN, "", false), wire(6, ^uint32(0), capture.TCPFlagACK|capture.TCPFlagPSH, "abcdef", false))
	split, err := Apply(f, Split(2))
	if err != nil {
		t.Fatal(err)
	}
	if len(split.Packets) != 4 || split.Packets[2].Decoded.TCP.Seq != 1 || split.Packets[1].Decoded.TCP.Flags&capture.TCPFlagPSH != 0 || split.Packets[3].Decoded.TCP.Flags&capture.TCPFlagPSH == 0 || split.Packets[2].Source[0].Start != 2 || split.Packets[2].Source[0].End != 4 {
		t.Fatalf("split sequence/spans/flags: %+v", split.Packets)
	}
	coalesced, err := Apply(split, Coalesce(8))
	if err != nil {
		t.Fatal(err)
	}
	if len(coalesced.Packets) != 2 || string(coalesced.Packets[1].Decoded.Payload) != "abcdef" || len(coalesced.Packets[1].Source) != 3 {
		t.Fatal("coalescing lost attribution")
	}
	reordered, err := Apply(split, Reorder(3, []int{2, 1, 0}))
	if err != nil {
		t.Fatal(err)
	}
	retransmitted, err := Apply(split, Retransmit([]int{1, 2}))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []Fixture{f, split, coalesced, reordered, retransmitted} {
		for _, mode := range []PositionMode{Sequence, SessionOffsets} {
			steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}) }, input, ReplayOptions{Position: mode, FailClosed: true, SimulateHandshake: true})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(kinds(steps), []string{"ab", "cd", "ef"}) {
				t.Fatalf("%v/%v: %v", input.Derived, mode, kinds(steps))
			}
		}
	}
	// Every output payload is independent of both the original and duplicates.
	retransmitted.Packets[1].Decoded.Payload[0] = 'X'
	if string(retransmitted.Packets[2].Decoded.Payload) != "ab" || string(f.Packets[1].Decoded.Payload) != "abcdef" {
		t.Fatal("aliased retransmission")
	}
	if len(split.Packets[0].Wire) != 0 || split.Packets[1].Time.Before(split.Packets[0].Time) || f.Packets[0].Wire == nil || len(f.Derived) != 0 {
		t.Fatal("derived wire/time/provenance contract")
	}
}
func TestTransformBarriersAndBounds(t *testing.T) {
	f := fixture(t, wire(6, 1, capture.TCPFlagSYN, "", false), wire(6, 2, 0, "ab", false), wire(6, 4, 0, "cd", false), wire(6, 8, 0, "ij", false), wire(6, 10, capture.TCPFlagFIN, "", false))
	coalesced, err := Apply(f, Coalesce(10))
	if err != nil {
		t.Fatal(err)
	}
	if len(coalesced.Packets) != 4 {
		t.Fatal("coalesced across gap or control")
	}
	for _, tr := range []Transform{Split(0), Split(MaxTransformPayload + 1), Coalesce(0), Coalesce(MaxTransformPayload + 1), Reorder(1, []int{0}), Reorder(2, []int{1, 1}), Reorder(2, []int{0, 2}), Retransmit([]int{0}), Retransmit([]int{-1}), Retransmit([]int{1, 1}), Retransmit([]int{99})} {
		if _, err := tr.Apply(f); err == nil {
			t.Fatal("accepted invalid transform")
		}
	}
	// UDP is datagram-atomic for every TCP transform, even if no change would result.
	udp := Fixture{Packets: readPackets(t, wire(17, 0, 0, "ab", false))}
	for _, tr := range []Transform{Split(10), Coalesce(10), Reorder(2, []int{1, 0}), Retransmit(nil)} {
		if _, err := tr.Apply(udp); err == nil {
			t.Fatal("transformed UDP")
		}
	}
	// Opposite-direction packets, including empty ACKs, are causal barriers.
	both := fixture(t, wire(6, 1, capture.TCPFlagSYN, "", false), wire(6, 50, capture.TCPFlagSYN|capture.TCPFlagACK, "", true), wire(6, 2, 0, "ab", false), wire(6, 51, 0, "cd", true), wire(6, 4, 0, "ef", false))
	result, err := Apply(both, Coalesce(20), Reorder(2, []int{1, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(Seeds(result), Seeds(both)) {
		t.Fatal("crossed response barrier")
	}
}
func TestSeedModes(t *testing.T) {
	f := fixture(t, wire(6, 10, capture.TCPFlagSYN, "", false), wire(6, 11, 0, "ab", false), wire(6, 13, 0, "cd", false))
	seeds := Seeds(f)
	streams, err := StreamSeeds(f)
	if err != nil || len(seeds) != 2 || len(streams) != 1 || string(streams[0]) != "abcd" {
		t.Fatalf("seeds %v %v %v", seeds, streams, err)
	}
	seeds[0][0] = 'X'
	streams[0][0] = 'Y'
	if string(f.Packets[1].Decoded.Payload) != "ab" {
		t.Fatal("seed aliases fixture")
	}
	transformed, err := Split(1).Apply(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StreamSeeds(transformed); err == nil {
		t.Fatal("accepted derivative stream seeds")
	}
	f.Packets[2].Decoded.TCP.Seq++
	if _, err := StreamSeeds(f); err == nil {
		t.Fatal("accepted gap seed")
	}
	f.Spec.Contiguous = false
	if _, err := StreamSeeds(f); err == nil {
		t.Fatal("accepted undeclared contiguity")
	}
}

func TestTransformEveryCuts(t *testing.T) {
	f := fixture(t, wire(6, 1, capture.TCPFlagSYN, "", false), wire(6, 2, capture.TCPFlagPSH, "abcde", false))
	if _, err := EveryCuts(f, 3); err == nil {
		t.Fatal("silently sampled cuts")
	}
	variants, err := EveryCuts(f, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(variants) != 4 {
		t.Fatal("missing cut")
	}
	for i, v := range variants {
		if len(v.Packets[1].Decoded.Payload) != i+1 || len(v.Packets[2].Decoded.Payload) != 4-i {
			t.Fatal("wrong cut schedule")
		}
		steps, err := Replay(func() *dpi.Manager { return dpi.NewManager(&fakeDecoder{}) }, v, ReplayOptions{})
		if err != nil || !reflect.DeepEqual(kinds(steps), []string{"ab", "cd"}) {
			t.Fatalf("cut replay: %v %v", err, kinds(steps))
		}
	}
	udp := Fixture{Packets: readPackets(t, wire(17, 0, 0, "a", false))}
	if _, err := EveryCuts(udp, 1); err == nil {
		t.Fatal("accepted UDP cuts")
	}
}
