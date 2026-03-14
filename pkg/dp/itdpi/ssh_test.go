// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func sshFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   6,
	}, time.Now())
}

func TestSSHPorts(t *testing.T) {
	d := NewSSHDecoder()
	tcp, udp := d.Ports()
	if len(udp) != 0 {
		t.Fatalf("expected no UDP ports, got %v", udp)
	}
	want := map[uint16]bool{22: true, 2222: true, 8022: true}
	for _, p := range tcp {
		if !want[p] {
			t.Fatalf("unexpected TCP port %d", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("missing TCP ports: %v", want)
	}
}

func TestSSHVersionExchange(t *testing.T) {
	d := NewSSHDecoder()
	st := sshFlowState(12345, 22)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("SSH-2.0-OpenSSH_8.9\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 22,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "ssh" {
		t.Errorf("proto=%q, want ssh", ev.Proto)
	}
	if ev.Kind != "version_exchange" {
		t.Errorf("kind=%q, want version_exchange", ev.Kind)
	}
	if v := ev.Attributes["version"]; v != "2.0" {
		t.Errorf("version=%v, want 2.0", v)
	}
	if s := ev.Attributes["software"]; s != "OpenSSH_8.9" {
		t.Errorf("software=%v, want OpenSSH_8.9", s)
	}
}

func TestSSHVersionExchangeWithComments(t *testing.T) {
	d := NewSSHDecoder()
	st := sshFlowState(12345, 22)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("SSH-2.0-OpenSSH_8.9 Ubuntu-3\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 22,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if c := ev.Attributes["comments"]; c != "Ubuntu-3" {
		t.Errorf("comments=%v, want Ubuntu-3", c)
	}
	if s := ev.Attributes["software"]; s != "OpenSSH_8.9" {
		t.Errorf("software=%v, want OpenSSH_8.9", s)
	}
}

func TestSSHVersion199Compat(t *testing.T) {
	d := NewSSHDecoder()
	st := sshFlowState(12345, 22)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("SSH-1.99-OpenSSH_7.4\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 22,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if v := ev.Attributes["version"]; v != "1.99" {
		t.Errorf("version=%v, want 1.99", v)
	}
	if s := ev.Attributes["software"]; s != "OpenSSH_7.4" {
		t.Errorf("software=%v, want OpenSSH_7.4", s)
	}
}

func TestSSHKexInit(t *testing.T) {
	d := NewSSHDecoder()
	st := sshFlowState(12345, 22)

	// Build a minimal SSH_MSG_KEXINIT binary packet.
	// Layout: [4 bytes packet_length][1 byte padding_length][1 byte msg_type=20][16 bytes cookie][name-lists...]
	kexAlg := "curve25519-sha256"
	hostKeyAlg := "ssh-ed25519"
	encAlg := "aes256-gcm@openssh.com"

	var payload []byte
	// 16 bytes cookie (zeros)
	payload = append(payload, make([]byte, 16)...)
	// name-list: kex_algorithms
	payload = appendNameList(payload, kexAlg)
	// name-list: server_host_key_algorithms
	payload = appendNameList(payload, hostKeyAlg)
	// name-list: encryption_algorithms_client_to_server
	payload = appendNameList(payload, encAlg)

	paddingLen := byte(4)
	padding := make([]byte, paddingLen)

	// packet_length = padding_length(1) + msg_type(1) + payload + padding
	pktLen := uint32(1 + 1 + len(payload) + int(paddingLen))

	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, pktLen)
	buf = append(buf, paddingLen) // padding_length
	buf = append(buf, 20)         // SSH_MSG_KEXINIT
	buf = append(buf, payload...)
	buf = append(buf, padding...)

	pkt := &dpi.ParsedPacket{
		Payload: buf,
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 22,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "kex_init" {
		t.Errorf("kind=%q, want kex_init", ev.Kind)
	}
	if k := ev.Attributes["kex_algorithm"]; k != kexAlg {
		t.Errorf("kex_algorithm=%v, want %s", k, kexAlg)
	}
	if e := ev.Attributes["encryption"]; e != encAlg {
		t.Errorf("encryption=%v, want %s", e, encAlg)
	}
}

func TestSSHNonSSHTraffic(t *testing.T) {
	d := NewSSHDecoder()
	st := sshFlowState(12345, 22)
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 22,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for non-SSH traffic, got %d", len(events))
	}
}

func TestSSHEmptyPayload(t *testing.T) {
	d := NewSSHDecoder()
	st := sshFlowState(12345, 22)
	pkt := &dpi.ParsedPacket{
		Payload: nil,
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 22,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty payload, got %d", len(events))
	}
}

// appendNameList appends a uint32-length-prefixed SSH name-list to buf.
func appendNameList(buf []byte, names string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(names)))
	buf = append(buf, names...)
	return buf
}
