// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package anomaly

import (
	"testing"
	"time"
)

func TestIEC104APCILifecycle(t *testing.T) {
	now := time.Unix(1, 0)
	var s IEC104APCI
	steps := []struct {
		frame IEC104APCIFrame
		want  string
	}{
		{IEC104APCIFrame{Format: "I"}, IEC104DataWhileStopped},
		{IEC104APCIFrame{Format: "U", UFunction: "startdt_act"}, ""},
		{IEC104APCIFrame{Direction: 1, Format: "U", UFunction: "startdt_con"}, ""},
		{IEC104APCIFrame{Format: "I", Send: 1}, ""},
		{IEC104APCIFrame{Format: "U", UFunction: "stopdt_act"}, ""},
		// The controlled station can still send until STOPDT con.
		{IEC104APCIFrame{Direction: 1, Format: "I", Receive: 2}, ""},
		{IEC104APCIFrame{Direction: 1, Format: "U", UFunction: "stopdt_con"}, ""},
		{IEC104APCIFrame{Direction: 1, Format: "I", Send: 1, Receive: 2}, IEC104DataWhileStopped},
		{IEC104APCIFrame{Direction: 1, Format: "U", UFunction: "startdt_con"}, ""},
		{IEC104APCIFrame{Direction: 1, Format: "I", Send: 2, Receive: 2}, ""},
	}
	for i, step := range steps {
		got := s.Observe(step.frame, now)
		if step.want == "" {
			if len(got) != 0 {
				t.Fatalf("step %d: %+v", i, got)
			}
		} else if len(got) != 1 || got[0].Type != step.want {
			t.Fatalf("step %d: %+v, want %s", i, got, step.want)
		}
	}
}

func TestIEC104APCISequences(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []IEC104APCIFrame
		want   string
	}{
		{"gap", []IEC104APCIFrame{{Format: "I", Send: 1}}, IEC104SendSequence},
		{"backwards", []IEC104APCIFrame{{Format: "I"}, {Format: "I"}}, IEC104SendSequence},
		{"unsent ACK", []IEC104APCIFrame{{Direction: 1, Format: "S", Receive: 1}}, IEC104AckSequence},
		{"backwards ACK", []IEC104APCIFrame{
			{Format: "I"}, {Direction: 1, Format: "S", Receive: 1}, {Direction: 1, Format: "S"},
		}, IEC104AckSequence},
		{"duplicate ACK", []IEC104APCIFrame{
			{Format: "I"}, {Direction: 1, Format: "S", Receive: 1}, {Direction: 1, Format: "S", Receive: 1},
		}, ""},
		{"bidirectional piggyback", []IEC104APCIFrame{
			{Format: "I"}, {Direction: 1, Format: "I", Receive: 1}, {Format: "I", Send: 1, Receive: 1},
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := IEC104APCI{started: true}
			var got []IEC104APCIFinding
			for _, f := range tc.frames {
				got = append(got, s.Observe(f, time.Unix(1, 0))...)
			}
			if tc.want == "" && len(got) == 0 {
				return
			}
			if len(got) != 1 || got[0].Type != tc.want {
				t.Fatalf("findings %+v, want %q", got, tc.want)
			}
		})
	}
}

func TestIEC104APCIStoppedAlertOncePerPeriod(t *testing.T) {
	var s IEC104APCI
	now := time.Unix(1, 0)
	alerts := 0
	var ns uint16
	send := func() {
		t.Helper()
		for _, f := range s.Observe(IEC104APCIFrame{Format: "I", Send: ns}, now) {
			if f.Type != IEC104DataWhileStopped {
				t.Fatalf("unexpected finding: %+v", f)
			}
			alerts++
		}
		ns++
	}
	u := func(fn string) {
		t.Helper()
		if got := s.Observe(IEC104APCIFrame{Direction: 1, Format: "U", UFunction: fn}, now); len(got) != 0 {
			t.Fatal(got)
		}
	}
	for range 100 {
		send()
	}
	if alerts != 1 {
		t.Fatalf("initial stopped period: alerts=%d, want 1", alerts)
	}
	// Neither repeated STOPDT confirmations nor STARTDT act re-arm it.
	u("stopdt_con")
	u("startdt_act")
	send()
	if alerts != 1 {
		t.Fatalf("re-armed without STARTDT con: alerts=%d", alerts)
	}
	u("startdt_con")
	send()
	u("stopdt_con")
	for range 100 {
		send()
	}
	if alerts != 2 {
		t.Fatalf("STOPDT -> STARTDT -> STOPDT: alerts=%d, want 2", alerts)
	}
}

func TestIEC104APCIWrap(t *testing.T) {
	s := IEC104APCI{started: true}
	now := time.Unix(1, 0)
	// Exercise every sequence, with a bounded outstanding window spanning
	// 32767 -> 0, including an ACK equal to each inclusive window endpoint.
	for n := 0; n <= 32768; n++ {
		ns := uint16(n & 32767)
		for _, f := range []IEC104APCIFrame{
			{Format: "I", Send: ns},
			{Direction: 1, Format: "S", Receive: ns},
			{Direction: 1, Format: "S", Receive: (ns + 1) & 32767},
		} {
			if got := s.Observe(f, now); len(got) != 0 {
				t.Fatalf("sequence %d: %+v", n, got)
			}
		}
	}
	for _, nr := range []uint16{0, 2} { // backwards, then ACK of unsent
		got := s.Observe(IEC104APCIFrame{Direction: 1, Format: "S", Receive: nr}, now)
		if len(got) != 1 || got[0].Type != IEC104AckSequence {
			t.Fatalf("ACK %d after wrap: %+v", nr, got)
		}
	}
}

func TestIEC104APCITestTimer(t *testing.T) {
	now := time.Unix(1, 0)
	for dir := 0; dir < 2; dir++ {
		t.Run([]string{"client", "server"}[dir], func(t *testing.T) {
			var s IEC104APCI
			act := IEC104APCIFrame{Direction: dir, Format: "U", UFunction: "testfr_act"}
			con := IEC104APCIFrame{Direction: 1 - dir, Format: "U", UFunction: "testfr_con"}
			s.Observe(act, now)
			s.Observe(act, now.Add(time.Second)) // cannot extend deadline
			s.Observe(IEC104APCIFrame{Direction: dir, Format: "U", UFunction: "testfr_con"}, now)
			if got := s.Expire(now.Add(IEC104T1 - time.Nanosecond)); len(got) != 0 {
				t.Fatal(got)
			}
			got := s.Expire(now.Add(IEC104T1))
			if len(got) != 1 || got[0].Type != IEC104TestTimeout || got[0].Direction != dir {
				t.Fatalf("expiry: %+v", got)
			}
			if got := s.Expire(now.Add(2 * IEC104T1)); len(got) != 0 {
				t.Fatalf("duplicate expiry: %+v", got)
			}
			s.Observe(act, now.Add(3*IEC104T1))
			if got := s.Observe(con, now.Add(4*IEC104T1-time.Second)); len(got) != 0 {
				t.Fatal(got)
			}
			if got := s.Expire(now.Add(5 * IEC104T1)); len(got) != 0 {
				t.Fatalf("confirmed activation: %+v", got)
			}
		})
	}
}

func TestIEC104APCILateConfirmation(t *testing.T) {
	var s IEC104APCI
	now := time.Unix(1, 0)
	s.Observe(IEC104APCIFrame{Format: "U", UFunction: "testfr_act"}, now)
	got := s.Observe(IEC104APCIFrame{Direction: 1, Format: "U", UFunction: "testfr_con"}, now.Add(IEC104T1))
	if len(got) != 1 || got[0].Type != IEC104TestTimeout {
		t.Fatalf("late confirmation hid expiry: %+v", got)
	}
}
