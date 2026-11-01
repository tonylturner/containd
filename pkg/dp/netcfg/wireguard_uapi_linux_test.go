// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func TestWireGuardUAPI(t *testing.T) {
	// Literal values come from linux/wireguard.h, not from our encoder.
	got := []int{
		wgCmdGetDevice, wgCmdSetDevice,
		wgDeviceAUnspec, wgDeviceAIfindex, wgDeviceAIfname, wgDeviceAPrivateKey, wgDeviceAPublicKey,
		wgDeviceAFlags, wgDeviceAListenPort, wgDeviceAFwmark, wgDeviceAPeers,
		wgPeerAUnspec, wgPeerAPublicKey, wgPeerAPresharedKey, wgPeerAFlags, wgPeerAEndpoint,
		wgPeerAPersistentKeepalive, wgPeerALastHandshakeTime, wgPeerARxBytes, wgPeerATxBytes, wgPeerAAllowedIPs, wgPeerAProtocolVersion,
		wgAllowedipAUnspec, wgAllowedipAFamily, wgAllowedipAIpaddr, wgAllowedipACidrMask,
		wgDeviceFReplacePeers, wgPeerFRemoveMe, wgPeerFReplaceAllowedIPs, wgPeerFUpdateOnly, nlaNested,
	}
	want := []int{0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 1, 1, 2, 4, 1 << 15}
	if !reflect.DeepEqual(got, want) || wgGenlName != "wireguard" || wgGenlVersion != 1 {
		t.Fatalf("WireGuard UAPI mismatch: %v, want %v", got, want)
	}
	raw, err := encodeSockaddr("192.0.2.7:51821")
	if err != nil || len(raw) != 16 || binary.NativeEndian.Uint16(raw[:2]) != unix.AF_INET ||
		binary.BigEndian.Uint16(raw[2:4]) != 51821 || !bytes.Equal(raw[4:8], []byte{192, 0, 2, 7}) {
		t.Fatalf("sockaddr_in encoding: %x %v", raw, err)
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if decoded, err := decodeKey32(key); err != nil || !bytes.Equal(decoded, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("key encoding: %v", err)
	}
	for _, bad := range []string{"invalid", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := decodeKey32(bad); err == nil {
			t.Fatal("accepted malformed key")
		}
	}
}

func TestWireGuardEncodingRejectsInvalidFields(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	for _, peer := range []config.WGPeer{
		{PublicKey: "invalid"},
		{PublicKey: key, PersistentKeepalive: -1},
		{PublicKey: key, PersistentKeepalive: 65536},
		{PublicKey: key, Endpoint: "192.0.2.1:65536"},
		{PublicKey: key, Endpoint: "192.0.2.1:not-a-port"},
		{PublicKey: key, AllowedIPs: []string{"invalid"}},
		{PublicKey: key, AllowedIPs: []string{"2001:db8::/64"}},
	} {
		if _, err := encodeWireGuardPeers([]config.WGPeer{peer}); err == nil {
			t.Fatalf("accepted invalid or unsupported peer: %+v", peer)
		}
	}
}

func TestWireGuardDumpFragmentsAndErrors(t *testing.T) {
	var status WireGuardStatus
	fragment := func(key byte, cidr string) {
		var data bytes.Buffer
		addNestedNLAttr(&data, 8, func(peers *bytes.Buffer) {
			addNestedNLAttr(peers, 0, func(peer *bytes.Buffer) {
				addNLAttr(peer, 1, bytes.Repeat([]byte{key}, 32))
				addNestedNLAttr(peer, 9, func(ips *bytes.Buffer) {
					addNestedNLAttr(ips, 0, func(ip *bytes.Buffer) {
						family, addr, mask, ok := parseCIDRForWG(cidr)
						if !ok {
							t.Fatal(cidr)
						}
						raw := make([]byte, 2)
						binary.NativeEndian.PutUint16(raw, family)
						addNLAttr(ip, 1, raw)
						addNLAttr(ip, 2, addr)
						addNLAttr(ip, 3, []byte{mask})
					})
				})
			})
		})
		parseWireGuardDeviceAttrs(&status, data.Bytes())
	}
	fragment(7, "192.0.2.0/25")
	fragment(7, "192.0.2.128/25")
	fragment(8, "198.51.100.0/24")
	if len(status.Peers) != 2 || len(status.Peers[0].AllowedIPs) != 2 || len(status.Peers[1].AllowedIPs) != 1 {
		t.Fatalf("lost multipart peers or allowed IPs: %+v", status)
	}
	raw := make([]byte, 4)
	code := -int32(unix.EPERM)
	binary.NativeEndian.PutUint32(raw, uint32(code))
	done, err := handleWireGuardStatusMessage(syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Seq: 17}, Data: raw,
	}, 17, &status)
	if !done || err != unix.EPERM {
		t.Fatalf("dump error lost: done=%v err=%v", done, err)
	}
}

// Requires a disposable Linux container with NET_ADMIN:
// CONTAIND_WIREGUARD_KERNEL_TEST=1 go test -run TestWireGuardKernelRoundTrip ./pkg/dp/netcfg
func TestWireGuardKernelRoundTrip(t *testing.T) {
	if os.Getenv("CONTAIND_WIREGUARD_KERNEL_TEST") != "1" {
		t.Skip("requires disposable Linux network namespace with NET_ADMIN")
	}
	t.Setenv("CONTAIND_WIREGUARD_STATE_PATH", filepath.Join(t.TempDir(), "links.json"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := func(value byte) *ecdh.PrivateKey {
		t.Helper()
		raw := bytes.Repeat([]byte{value}, 32)
		raw[0] &= 248
		raw[31] = raw[31]&127 | 64
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	private, peer1, peer2 := key(17), key(34), key(51)
	cfg := config.WireGuardConfig{
		Enabled: true, Interface: "ct-wg-uapi", ListenPort: 51829,
		PrivateKey:  base64.StdEncoding.EncodeToString(private.Bytes()),
		AddressCIDR: "198.51.100.1/24",
		Peers: []config.WGPeer{
			{PublicKey: base64.StdEncoding.EncodeToString(peer1.PublicKey().Bytes()), Endpoint: "192.0.2.101:51821", PersistentKeepalive: 23, AllowedIPs: []string{"198.51.100.10/32", "203.0.113.0/25"}},
			{PublicKey: base64.StdEncoding.EncodeToString(peer2.PublicKey().Bytes()), Endpoint: "192.0.2.102:51822", PersistentKeepalive: 47, AllowedIPs: []string{"198.51.100.11/32", "203.0.113.128/25"}},
		},
	}
	defer func() {
		if err := deleteLink(cfg.Interface); err != nil {
			t.Error(err)
		}
	}()
	if err := ApplyWireGuard(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	assertWireGuardKernelConfig(t, ctx, cfg, private.PublicKey().Bytes())
	// Full replacement must remove stale peers and stale allowed IPs.
	cfg.Peers = cfg.Peers[:1]
	cfg.Peers[0].AllowedIPs = []string{"198.51.100.12/32"}
	if err := ApplyWireGuard(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	assertWireGuardKernelConfig(t, ctx, cfg, private.PublicKey().Bytes())
	cfg.Peers = nil
	if err := ApplyWireGuard(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	assertWireGuardKernelConfig(t, ctx, cfg, private.PublicKey().Bytes())
}

func assertWireGuardKernelConfig(t *testing.T, ctx context.Context, cfg config.WireGuardConfig, public []byte) {
	t.Helper()
	nic, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := openWireGuardNetlinkSocket()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	family, err := genlFamilyID(ctx, fd, "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	seq := atomic.AddUint32(&nlSeq, 1)
	req := buildWireGuardStatusRequest(seq, family, nic.Index)
	if req[unix.NLMSG_HDRLEN] != 0 {
		t.Fatal("GET_DEVICE command must be zero")
	}
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	attrs := readWireGuardKernelDump(t, ctx, fd, seq)
	fields := map[uint16][]byte{}
	var peers []netlinkAttr
	for _, attr := range attrs {
		fields[attr.Type&0x3fff] = attr.Value
		if attr.Type&0x3fff == 8 {
			peers = append(peers, parseNetlinkAttrs(attr.Value)...)
		}
	}
	// Independent literal ids prevent a mirrored encoder/decoder bug from
	// making the round-trip test pass.
	if string(bytes.TrimRight(fields[2], "\x00")) != cfg.Interface ||
		!bytes.Equal(fields[3], mustWireGuardKey(t, cfg.PrivateKey)) ||
		!bytes.Equal(fields[4], public) || len(fields[6]) != 2 ||
		int(binary.NativeEndian.Uint16(fields[6])) != cfg.ListenPort {
		t.Fatal("kernel device fields did not round-trip")
	}
	if len(peers) != len(cfg.Peers) {
		t.Fatalf("kernel has %d peers, want %d", len(peers), len(cfg.Peers))
	}
	wantPeers := map[string]config.WGPeer{}
	for _, peer := range cfg.Peers {
		wantPeers[peer.PublicKey] = peer
	}
	for _, nested := range peers {
		if nested.Type != 1<<15 {
			t.Fatalf("invalid peer nesting: %#x", nested.Type)
		}
		fields := map[uint16][]byte{}
		for _, attr := range parseNetlinkAttrs(nested.Value) {
			fields[attr.Type&0x3fff] = attr.Value
		}
		peer, ok := wantPeers[base64.StdEncoding.EncodeToString(fields[1])]
		if !ok || len(fields[5]) != 2 || int(binary.NativeEndian.Uint16(fields[5])) != peer.PersistentKeepalive ||
			decodeSockaddr(fields[4]) != peer.Endpoint {
			t.Fatal("kernel peer key, endpoint or keepalive did not round-trip")
		}
		ips := decodeAllowedIPs(fields[9])
		sort.Strings(ips)
		wantIPs := append([]string(nil), peer.AllowedIPs...)
		sort.Strings(wantIPs)
		if !reflect.DeepEqual(ips, wantIPs) {
			t.Fatalf("kernel allowed IPs: %v, want %v", ips, wantIPs)
		}
	}
	// The production GET_DEVICE reader must agree with the independent read.
	status, err := GetWireGuardStatus(ctx, cfg.Interface)
	if err != nil || !status.Present || status.PublicKey != base64.StdEncoding.EncodeToString(public) ||
		status.ListenPort != cfg.ListenPort || len(status.Peers) != len(cfg.Peers) {
		t.Fatalf("kernel status: %+v %v", status, err)
	}
}

func mustWireGuardKey(t *testing.T, key string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readWireGuardKernelDump(t *testing.T, ctx context.Context, fd int, seq uint32) []netlinkAttr {
	t.Helper()
	if err := setWireGuardRecvDeadline(fd, wireGuardStatusDeadline(ctx)); err != nil {
		t.Fatal(err)
	}
	var attrs []netlinkAttr
	for {
		buf := make([]byte, 1<<16)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range msgs {
			if msg.Header.Seq != seq {
				continue
			}
			if msg.Header.Type == unix.NLMSG_DONE || msg.Header.Type == unix.NLMSG_ERROR {
				if err := netlinkMessageError(msg.Data); err != nil {
					t.Fatal(err)
				}
				if msg.Header.Type == unix.NLMSG_DONE {
					return attrs
				}
			} else if len(msg.Data) >= 4 {
				attrs = append(attrs, parseNetlinkAttrs(msg.Data[4:])...)
			}
		}
	}
}
