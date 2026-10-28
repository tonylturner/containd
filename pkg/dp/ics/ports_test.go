// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ics

import (
	"strings"
	"testing"
)

func TestDecoderPorts(t *testing.T) {
	ports := DecoderPorts()
	if len(ports) != 6 {
		t.Fatalf("ports = %v", ports)
	}
	for i := 1; i < len(ports); i++ {
		prev, cur := ports[i-1], ports[i]
		if prev.Port > cur.Port || prev.Port == cur.Port && prev.Transport >= cur.Transport {
			t.Fatalf("ports not ascending: %v", ports)
		}
	}
	for _, p := range ports {
		if !Supported(p.Protocol) {
			t.Errorf("%s names an unsupported decoder", p)
		}
		if p.Transport != TCP && p.Transport != UDP {
			t.Errorf("%s has transport %d", p, p.Transport)
		}
	}
}

func TestProtocolPortOn(t *testing.T) {
	for _, p := range DecoderPorts() {
		if !IsProtocolPortOn(strings.ToUpper(p.Protocol), p.Transport, p.Port) {
			t.Errorf("%s not on transport %d", p, p.Transport)
		}
	}
	for _, c := range []struct {
		protocol  string
		transport uint8
		port      uint16
	}{
		{"cip", TCP, 2222}, {"modbus", UDP, 502}, {"dnp3", UDP, 20000},
		{"iec104", UDP, 2404}, {"modbus", TCP, 503}, {"cip", TCP, 2404},
		{"iec104", TCP, 502}, {"", TCP, 502}, {"http", TCP, 80}, {"cip", 1, 44818},
	} {
		if IsProtocolPortOn(c.protocol, c.transport, c.port) {
			t.Errorf("%s/%d reported on transport %d", c.protocol, c.port, c.transport)
		}
	}
}

func TestDecoderPortOn(t *testing.T) {
	for _, p := range DecoderPorts() {
		if !IsDecoderPortOn(p.Transport, p.Port) {
			t.Errorf("%s not on transport %d", p, p.Transport)
		}
	}
	for _, c := range []struct {
		transport uint8
		port      uint16
	}{{UDP, 502}, {UDP, 20000}, {UDP, 2404}, {TCP, 2222}, {1, 502}, {TCP, 80}, {UDP, 53}} {
		if IsDecoderPortOn(c.transport, c.port) {
			t.Errorf("%d/%d reported as a decoder port", c.transport, c.port)
		}
	}
}

func TestDecoderPortIn(t *testing.T) {
	if p, ok := DecoderPortIn(500, 600); !ok || p.String() != "modbus/502" {
		t.Fatalf("DecoderPortIn(500, 600) = %v, %v", p, ok)
	}
	if p, ok := DecoderPortIn(1, 65535); !ok || p.Port != 502 {
		t.Fatalf("DecoderPortIn(1, 65535) = %v, %v", p, ok)
	}
	if p, ok := DecoderPortIn(2222, 2222); !ok || p.String() != "cip/2222" || p.Transport != UDP {
		t.Fatalf("DecoderPortIn(2222, 2222) = %v, %v", p, ok)
	}
	if p, ok := DecoderPortIn(44818, 44818); !ok || p.String() != "cip/44818" {
		t.Fatalf("DecoderPortIn(44818, 44818) = %v, %v", p, ok)
	}
	if _, ok := DecoderPortIn(503, 2221); ok {
		t.Fatal("503-2221 reported a decoder port")
	}
}
