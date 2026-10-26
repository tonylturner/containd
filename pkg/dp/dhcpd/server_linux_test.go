// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dhcpd

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const testMAC = "02:00:00:00:00:01"

func testRuntime(authoritative bool) dhcpRuntime {
	return dhcpRuntime{dev: "lan", authoritative: authoritative,
		serverIP: net.ParseIP("192.0.2.1"), mask: net.CIDRMask(24, 32),
		pool:         pool{Start: net.ParseIP("192.0.2.10"), End: net.ParseIP("192.0.2.20")},
		leaseSeconds: 3600, manager: &Manager{leases: map[string]Lease{}},
	}
}

func requestPacket(kind byte, requested, ciaddr, server, relay string) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = dhcpOpRequest, dhcpHtypeEthernet, dhcpHlenEthernet
	binary.BigEndian.PutUint32(p[4:8], 42)
	copy(p[12:16], net.ParseIP(ciaddr).To4())
	copy(p[24:28], net.ParseIP(relay).To4())
	hw, _ := net.ParseMAC(testMAC)
	copy(p[28:34], hw)
	binary.BigEndian.PutUint32(p[236:240], dhcpMagicCookie)
	p = appendOpt(p, dhcpOptMsgType, []byte{kind})
	if requested != "" {
		p = appendOpt(p, dhcpOptRequestIP, net.ParseIP(requested).To4())
	}
	if server != "" {
		p = appendOpt(p, dhcpOptServerID, net.ParseIP(server).To4())
	}
	return append(p, dhcpOptEnd)
}

func replyOption(pkt []byte, code byte) []byte {
	for i := 240; i+1 < len(pkt) && pkt[i] != dhcpOptEnd; {
		n := int(pkt[i+1])
		if i+2+n > len(pkt) {
			return nil
		}
		if pkt[i] == code {
			return pkt[i+2 : i+2+n]
		}
		i += 2 + n
	}
	return nil
}

func TestRequestPackets(t *testing.T) {
	cases := []struct {
		name, requested, ciaddr, server, relay, lease, otherLease, reservation string
		unserved                                                               bool
		want                                                                   byte
	}{
		{name: "off subnet reboot", requested: "198.51.100.10", want: dhcpMsgNak},
		{name: "unknown reboot", requested: "192.0.2.10", want: dhcpMsgNak},
		{name: "known reboot", requested: "192.0.2.10", lease: "192.0.2.10", want: dhcpMsgAck},
		{name: "reserved reboot", requested: "192.0.2.10", reservation: "192.0.2.10", want: dhcpMsgAck},
		{name: "valid selection", requested: "192.0.2.10", server: "192.0.2.1", want: dhcpMsgAck},
		{name: "valid renewal", ciaddr: "192.0.2.10", lease: "192.0.2.10", want: dhcpMsgAck},
		{name: "off subnet renewal", ciaddr: "198.51.100.10", lease: "198.51.100.10", want: dhcpMsgNak},
		{name: "unknown renewal", ciaddr: "192.0.2.10", want: dhcpMsgNak},
		{name: "outside pool", requested: "192.0.2.30", lease: "192.0.2.30", want: dhcpMsgNak},
		{name: "stale lease must not override requested IP", requested: "192.0.2.11", lease: "192.0.2.10", want: dhcpMsgNak},
		{name: "other client owns address", requested: "192.0.2.10", server: "192.0.2.1", otherLease: "192.0.2.10", want: dhcpMsgNak},
		{name: "wrong reservation", requested: "192.0.2.11", server: "192.0.2.1", reservation: "192.0.2.10", want: dhcpMsgNak},
		{name: "foreign server", requested: "198.51.100.10", server: "192.0.2.2"},
		{name: "relay", requested: "198.51.100.10", relay: "198.51.100.1"},
		{name: "no requested address"},
		{name: "malformed renewal", ciaddr: "192.0.2.10", requested: "192.0.2.11"},
		{name: "unserved subnet", requested: "198.51.100.10", unserved: true},
	}
	for _, tc := range cases {
		for _, authority := range []bool{false, true} {
			mode := "silent"
			if authority {
				mode = "authoritative"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				rt := testRuntime(authority)
				if tc.unserved {
					rt.pool.Start = net.ParseIP("203.0.113.10")
				}
				if tc.lease != "" {
					rt.manager.upsertLease(rt.dev, testMAC, tc.lease, "", 3600)
				}
				if tc.otherLease != "" {
					rt.manager.upsertLease(rt.dev, "02:00:00:00:00:02", tc.otherLease, "", 3600)
				}
				if tc.reservation != "" {
					rt.reservations = map[string]string{testMAC: tc.reservation}
				}
				req, err := parseRequest(requestPacket(dhcpMsgRequest, tc.requested, tc.ciaddr, tc.server, tc.relay))
				if err != nil {
					t.Fatal(err)
				}
				pkt, err := replyToDHCPRequest(rt, req)
				if err != nil {
					t.Fatal(err)
				}
				want := tc.want
				if !authority && want == dhcpMsgNak {
					want = 0
				}
				if want == 0 {
					if len(pkt) != 0 {
						t.Fatalf("expected silence, got %x", pkt)
					}
					return
				}
				if len(pkt) < 240 || pkt[0] != dhcpOpReply || binary.BigEndian.Uint32(pkt[4:8]) != 42 {
					t.Fatalf("invalid reply: %x", pkt)
				}
				if got := replyOption(pkt, dhcpOptMsgType); len(got) != 1 || got[0] != want {
					t.Fatalf("message type %v, want %d", got, want)
				}
				if got := replyOption(pkt, dhcpOptServerID); !net.IP(got).Equal(rt.serverIP) {
					t.Fatalf("server-id %v", got)
				}
				if want == dhcpMsgNak {
					if !net.IP(pkt[16:20]).Equal(net.IPv4zero) || binary.BigEndian.Uint16(pkt[10:12])&0x8000 == 0 {
						t.Fatal("NAK must have zero yiaddr and broadcast flag")
					}
					if len(replyOption(pkt, dhcpOptLeaseTime)) != 0 || len(replyOption(pkt, dhcpOptSubnetMask)) != 0 {
						t.Fatal("NAK includes lease options")
					}
				} else {
					address := tc.requested
					if address == "" {
						address = tc.ciaddr
					}
					if !net.IP(pkt[16:20]).Equal(net.ParseIP(address)) {
						t.Fatalf("ACK changed client address: %v", net.IP(pkt[16:20]))
					}
					if ip, ok := rt.manager.lookupLeaseIP(rt.dev, testMAC); !ok || ip != address {
						t.Fatalf("lease not saved: %s", ip)
					}
				}
			})
		}
	}
}

func TestDiscoverExhaustionIsSilent(t *testing.T) {
	for _, authority := range []bool{false, true} {
		rt := testRuntime(authority)
		rt.pool.End = rt.pool.Start
		rt.manager.upsertLease(rt.dev, "02:00:00:00:00:02", rt.pool.Start.String(), "", 3600)
		req, err := parseRequest(requestPacket(dhcpMsgDiscover, "", "", "", ""))
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := replyToDHCPRequest(rt, req)
		if err != nil || len(pkt) != 0 {
			t.Fatalf("exhausted DISCOVER got %x, %v", pkt, err)
		}
	}
}

func TestOffersRespectReservations(t *testing.T) {
	rt := testRuntime(false)
	rt.reservations = map[string]string{"02:00:00:00:00:02": "192.0.2.10"}
	req, err := parseRequest(requestPacket(dhcpMsgDiscover, "192.0.2.10", "", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := replyToDHCPRequest(rt, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) < 240 || !net.IP(pkt[16:20]).Equal(net.ParseIP("192.0.2.11")) {
		t.Fatalf("offer stole reservation: %x", pkt)
	}
}

func TestAuthorityChangeRestartsListener(t *testing.T) {
	rt := testRuntime(false)
	l := listener{pool: rt.pool, cfg: config.DHCPConfig{}}
	if dhcpListenerNeedsRestart(l, config.DHCPConfig{}, rt.pool) {
		t.Fatal("unchanged listener needs restart")
	}
	if !dhcpListenerNeedsRestart(l, config.DHCPConfig{Authoritative: true}, rt.pool) {
		t.Fatal("authority change must restart listener")
	}
}

func TestMalformedAddressOptionsAreRejected(t *testing.T) {
	for _, tail := range [][]byte{
		{dhcpOptServerID}, {dhcpOptServerID, 4, 192}, {dhcpOptServerID, 1, 1},
		{dhcpOptRequestIP, 1, 1}, {dhcpOptMsgType, 1, dhcpMsgRequest},
	} {
		pkt := requestPacket(dhcpMsgRequest, "192.0.2.10", "", "", "")
		pkt = append(pkt[:len(pkt)-1], tail...)
		if _, err := parseRequest(pkt); err == nil {
			t.Fatalf("accepted malformed options: %x", tail)
		}
	}
}

func TestRequestsCannotUseProtectedAddresses(t *testing.T) {
	for _, address := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.255", "192.0.2.10"} {
		for _, authority := range []bool{false, true} {
			rt := testRuntime(authority)
			rt.pool = pool{Start: net.ParseIP("192.0.2.0"), End: net.ParseIP("192.0.2.255")}
			rt.reservations = map[string]string{"02:00:00:00:00:02": "192.0.2.10"}
			req, err := parseRequest(requestPacket(dhcpMsgRequest, address, "", "192.0.2.1", ""))
			if err != nil {
				t.Fatal(err)
			}
			pkt, err := replyToDHCPRequest(rt, req)
			if err != nil {
				t.Fatal(err)
			}
			if !authority && len(pkt) != 0 {
				t.Fatalf("passive mode replied for protected address %s", address)
			}
			if authority {
				if kind := replyOption(pkt, dhcpOptMsgType); len(kind) != 1 || kind[0] != dhcpMsgNak {
					t.Fatalf("protected address %s was not NAKed", address)
				}
			}
		}
	}
}

func TestUnservedInterfaceIsSilent(t *testing.T) {
	rt := testRuntime(true)
	rt.dev = ""
	req, err := parseRequest(requestPacket(dhcpMsgRequest, "198.51.100.10", "", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := replyToDHCPRequest(rt, req)
	if err != nil || len(pkt) != 0 {
		t.Fatalf("unserved interface replied: %x, %v", pkt, err)
	}
}
