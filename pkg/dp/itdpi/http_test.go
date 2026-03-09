// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package itdpi

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func httpFlowState(srcPort, dstPort uint16) *flow.State {
	return flow.NewState(flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   6,
	}, time.Now())
}

func TestHTTPPorts(t *testing.T) {
	d := NewHTTPDecoder()
	tcp, udp := d.Ports()
	if len(udp) != 0 {
		t.Fatalf("expected no UDP ports, got %v", udp)
	}
	want := map[uint16]bool{80: true, 8080: true, 8000: true, 3128: true}
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

func TestHTTPGetRequest(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 80)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 80,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "http" {
		t.Errorf("proto=%q, want http", ev.Proto)
	}
	if ev.Kind != "request" {
		t.Errorf("kind=%q, want request", ev.Kind)
	}
	if m := ev.Attributes["method"]; m != "GET" {
		t.Errorf("method=%v, want GET", m)
	}
	if p := ev.Attributes["path"]; p != "/index.html" {
		t.Errorf("path=%v, want /index.html", p)
	}
	if h := ev.Attributes["host"]; h != "example.com" {
		t.Errorf("host=%v, want example.com", h)
	}
}

func TestHTTPPostRequest(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 80)
	body := "key=value&foo=bar"
	raw := "POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 17\r\n\r\n" + body
	pkt := &dpi.ParsedPacket{
		Payload: []byte(raw),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 80,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "request" {
		t.Errorf("kind=%q, want request", ev.Kind)
	}
	if m := ev.Attributes["method"]; m != "POST" {
		t.Errorf("method=%v, want POST", m)
	}
	if p := ev.Attributes["path"]; p != "/api/data" {
		t.Errorf("path=%v, want /api/data", p)
	}
}

func TestHTTPResponse(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(80, 12345)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"),
		Proto:   "tcp",
		SrcPort: 80,
		DstPort: 12345,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "response" {
		t.Errorf("kind=%q, want response", ev.Kind)
	}
	if s := ev.Attributes["status"]; s != "200" {
		t.Errorf("status=%v, want 200", s)
	}
}

func TestHTTPH2Preface(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 80)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 80,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "http2" {
		t.Errorf("proto=%q, want http2", ev.Proto)
	}
	if ev.Kind != "preface" {
		t.Errorf("kind=%q, want preface", ev.Kind)
	}
}

func TestHTTPConnectProxy(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 3128)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 3128,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "request" {
		t.Errorf("kind=%q, want request", ev.Kind)
	}
	if m := ev.Attributes["method"]; m != "CONNECT" {
		t.Errorf("method=%v, want CONNECT", m)
	}
	if tgt := ev.Attributes["target"]; tgt != "www.example.com:443" {
		t.Errorf("target=%v, want www.example.com:443", tgt)
	}
}

func TestHTTPShortPayload(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 80)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("GE"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 80,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for short payload, got %d", len(events))
	}
}

func TestHTTPNonHTTPTraffic(t *testing.T) {
	d := NewHTTPDecoder()
	st := httpFlowState(12345, 80)
	pkt := &dpi.ParsedPacket{
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 80,
	}
	events, err := d.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("OnPacket error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events for non-HTTP traffic, got %d", len(events))
	}
}
