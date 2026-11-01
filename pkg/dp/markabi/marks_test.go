// SPDX-License-Identifier: Apache-2.0
package markabi_test

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
)

func TestAllocation(t *testing.T) {
	values := []uint32{markabi.OwnedForwardCtBit, markabi.AdmittedBit, markabi.ParityBit,
		markabi.AdmissionCtMask, markabi.QueueMarkMask, markabi.EnvelopeMark, markabi.HandshakeMark,
		markabi.ObservedMark, markabi.EnforceScopeMark, markabi.NonAdmitMark, markabi.ContinuationSkbMask}
	want := []uint32{1, 2, 4, 6, 0x0f000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x1f000000}
	for i, v := range values {
		if v != want[i] {
			t.Fatalf("constant %d = %#x, want %#x", i, v, want[i])
		}
	}
	gateCT := enforce.GateCtMark | enforce.GateUpstreamCtMark | enforce.GateMasqSelCtMark | enforce.GateZoneCtMask
	gateSKB := enforce.GateLocalPktMark | enforce.GateUpstreamSockMark | enforce.GateMasqSockMark
	if gateCT&(markabi.OwnedForwardCtBit|markabi.AdmissionCtMask) != 0 || gateSKB&markabi.ContinuationSkbMask != 0 {
		t.Fatal("gate and policy mark allocations overlap")
	}
	if markabi.AdmittedBit|markabi.ParityBit != markabi.AdmissionCtMask || markabi.QueueMarkMask|markabi.NonAdmitMark != markabi.ContinuationSkbMask {
		t.Fatal("mask composition")
	}
}

func TestMaskedWrites(t *testing.T) {
	for _, old := range []uint32{0, ^uint32(0), 0x00f2ffab} {
		for _, p := range []uint32{0, markabi.ParityBit} {
			got := markabi.Admit(old, p)
			if got&markabi.AdmissionCtMask != markabi.AdmittedBit|p || got&^markabi.AdmissionCtMask != old&^markabi.AdmissionCtMask {
				t.Fatal("admission overwrote foreign bits")
			}
			if markabi.ClearAdmission(got) != got&^markabi.AdmittedBit {
				t.Fatal("clear")
			}
		}
		for _, nonAdmit := range []bool{false, true} {
			got := markabi.Continue(old, nonAdmit)
			want := markabi.ObservedMark
			if nonAdmit {
				want |= markabi.NonAdmitMark
			}
			if got&markabi.ContinuationSkbMask != want || markabi.Clean(got) != old&^markabi.ContinuationSkbMask {
				t.Fatal("continuation")
			}
		}
		if got := markabi.Queue(old, ^uint32(0)); got&markabi.ContinuationSkbMask != markabi.EnvelopeMark|markabi.HandshakeMark|markabi.EnforceScopeMark || markabi.Clean(got) != markabi.Clean(old) {
			t.Fatal("queue")
		}
	}
	if !markabi.ValidParity(0) || !markabi.ValidParity(markabi.ParityBit) || markabi.ValidParity(1) {
		t.Fatal("parity")
	}
}
