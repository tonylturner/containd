// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestTransportExpiryPreservesRetentionBoundary(t *testing.T) {
	_, r, _ := newTransportTest(t, &transportCTFake{})
	now := time.Now()
	r.pruneAliases(now)
	ev := natEvidence()
	verified := &flow.Connection{ID: "test", Status: "resolved", Evidence: &ev}
	tuple := natEvidence().Original
	r.storeAlias(tuple, &transportAlias{connection: verified, expires: now})
	r.pruneAliases(now.Add(30 * time.Second))
	if len(r.aliases) != 1 {
		t.Fatal("verified history expired at strict boundary")
	}
	r.pruneAliases(now.Add(30*time.Second + time.Nanosecond))
	if len(r.aliases) != 0 || r.expiry.Len() != 0 || len(r.expiry.index) != 0 {
		t.Fatal("verified history not reclaimed")
	}
	r.storeAlias(tuple, &transportAlias{connection: &flow.Connection{}, expires: now})
	r.pruneAliases(now)
	if len(r.aliases) != 0 {
		t.Fatal("negative alias retained at expiry")
	}
}

func TestTransportExpiryRefreshStaysBounded(t *testing.T) {
	_, r, _ := newTransportTest(t, &transportCTFake{})
	now := time.Now()
	r.pruneAliases(now)
	for i := range transportAliasLimit {
		tuple := natEvidence().Original
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(i))
		r.storeAlias(tuple, &transportAlias{connection: &flow.Connection{}, expires: now.Add(time.Second)})
	}
	tuple := natEvidence().Original
	tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), 0)
	for range 100 {
		r.storeAlias(tuple, &transportAlias{connection: &flow.Connection{}, expires: now})
		r.storeAlias(tuple, &transportAlias{connection: &flow.Connection{}, expires: now.Add(2 * time.Second)})
	}
	if r.expiry.Len() != transportAliasLimit || len(r.expiry.index) != transportAliasLimit {
		t.Fatal("refresh accumulated stale expiry nodes")
	}
	r.pruneAliases(now.Add(time.Second))
	if len(r.aliases) != 1 || r.aliases[tuple] == nil {
		t.Fatal("refresh or full-table expiry lost the retained tuple")
	}
	r.pruneAliases(now.Add(2 * time.Second))
	if len(r.aliases) != 0 {
		t.Fatal("refreshed alias not reclaimed")
	}
}

func TestTransportExpiryReplacementKeepsPeer(t *testing.T) {
	_, r, _ := newTransportTest(t, &transportCTFake{})
	now := time.Now()
	r.pruneAliases(now)
	ev := natEvidence()
	a := &transportAlias{connection: &flow.Connection{Status: "resolved", Evidence: &ev}, expires: now}
	r.storeAlias(ev.Original, a)
	r.storeAlias(ev.Reply, a)
	r.storeAlias(ev.Original, &transportAlias{connection: &flow.Connection{}, expires: now})
	r.pruneAliases(now)
	if len(r.aliases) != 1 || r.aliases[ev.Reply] != a || r.expiry.Len() != 1 {
		t.Fatal("replacing one alias expired its shared peer")
	}
}

func TestTransportAdmissionRetainsCaptureOwnedBytes(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{})
	raw := make([]byte, 43)
	raw[0], raw[9], raw[32] = 0x45, 6, 0x50
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
	copy(raw[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(raw[20:], 41000)
	binary.BigEndian.PutUint16(raw[22:], 502)
	copy(raw[40:], []byte{1, 2, 3})
	pkt := capture.DecodeIPPacket(raw)
	if pkt.Invalid != "" {
		t.Fatal(pkt.Invalid)
	}
	r.admit(e, pkt)
	p := <-r.queue
	if &p.packet.Payload[0] != &pkt.Payload[0] || &p.packet.SrcIP[0] != &pkt.SrcIP[0] || &p.packet.DstIP[0] != &pkt.DstIP[0] {
		t.Fatal("admission redundantly cloned capture-owned data")
	}
	clear(raw)
	if string(p.packet.Payload) != "\x01\x02\x03" || p.packet.SrcIP.String() != "10.0.0.1" || p.packet.DstIP.String() != "10.0.0.2" {
		t.Fatal("queue retained the receive buffer")
	}
	r.releaseAdmission(p)
	if r.count.Load() != 0 || r.bytes.Load() != 0 {
		t.Fatal("admission did not release its budget")
	}
}
