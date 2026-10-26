// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
)

func dnp3CRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

// dnp3Read decodes a real DNP3 read request carrying the given object
// headers (group, variation, qualifier 0x06 "all objects").
func dnp3Read(t *testing.T, groups ...byte) dpi.Event {
	t.Helper()
	user := []byte{0xC0, 0xC0, 0x01}
	for _, g := range groups {
		user = append(user, g, 0x01, 0x06)
	}
	hdr := []byte{0x05, 0x64, byte(5 + len(user)), 0xC4, 0x01, 0x00, 0x02, 0x00}
	frame := binary.LittleEndian.AppendUint16(append([]byte(nil), hdr...), dnp3CRC(hdr))
	for len(user) > 0 {
		n := min(16, len(user))
		frame = append(frame, user[:n]...)
		frame = binary.LittleEndian.AppendUint16(frame, dnp3CRC(user[:n]))
		user = user[n:]
	}
	key := flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: 20000, Proto: 6}
	evs, err := dnp3.NewDecoder().OnPacket(flow.NewState(key, time.Now()), &dpi.ParsedPacket{Payload: frame, Proto: "tcp"})
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode: events=%d err=%v", len(evs), err)
	}
	return evs[0]
}

func matched(e *Engine, ev dpi.Event, id string) bool {
	for _, m := range e.Match(ev) {
		if m.Signature.ID == id {
			return true
		}
	}
	return false
}

func TestDNP3Group70SignatureUsesExactTokens(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	cases := []struct {
		groups []byte
		want   bool
	}{
		{[]byte{70}, true},
		{[]byte{1, 70}, true},
		{[]byte{7}, false},
		{[]byte{170}, false},
		{[]byte{1, 2}, false},
	}
	for _, c := range cases {
		ev := dnp3Read(t, c.groups...)
		raw, err := json.Marshal(ev.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		rt := ev
		if err := json.Unmarshal(raw, &rt.Attributes); err != nil {
			t.Fatal(err)
		}
		for _, e2 := range []dpi.Event{ev, rt} {
			if got := matched(e, e2, "DNP3-FILE-AUTH"); got != c.want {
				t.Fatalf("groups %v (object_groups=%v): match=%v want %v", c.groups, e2.Attributes["object_groups"], got, c.want)
			}
		}
	}
}

func TestHasTokenCondition(t *testing.T) {
	cond := Condition{Field: "tags", Op: "has_token", Value: float64(7)}
	for _, tc := range []struct {
		val  any
		want bool
	}{
		{"7", true},
		{"1, 7 ,9", true},
		{"17,70", false},
		{[]string{"7"}, true},
		{[]any{"70", "7"}, true},
		{[]any{"7", 7}, false},
		{nil, false},
		{7, false},
	} {
		if got := evalCondition(cond, tc.val); got != tc.want {
			t.Fatalf("has_token(%v) = %v, want %v", tc.val, got, tc.want)
		}
	}
	if evalCondition(Condition{Op: "has_token", Value: 7.5}, "7") {
		t.Fatal("fractional token must not match")
	}
}
