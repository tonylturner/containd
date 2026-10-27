// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ics

import "testing"

func TestDecoderPorts(t *testing.T) {
	ports := DecoderPorts()
	if len(ports) != 5 {
		t.Fatalf("ports = %v", ports)
	}
	for i := 1; i < len(ports); i++ {
		if ports[i-1].Port >= ports[i].Port {
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
	for proto, port := range map[string]uint16{"modbus": 502, "cip": 2222, "iec104": 2404, "dnp3": 20000, "CIP": 44818} {
		if !IsDecoderPort(proto, port) {
			t.Errorf("%s/%d not a decoder port", proto, port)
		}
	}
	for proto, port := range map[string]uint16{"modbus": 503, "cip": 2404, "iec104": 502, "": 502, "http": 80} {
		if IsDecoderPort(proto, port) {
			t.Errorf("%s/%d reported as a decoder port", proto, port)
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
	}{{UDP, 502}, {UDP, 20000}, {UDP, 44818}, {UDP, 2404}, {TCP, 2222}, {1, 502}, {TCP, 80}, {UDP, 53}} {
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
