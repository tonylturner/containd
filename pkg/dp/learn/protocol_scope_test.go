// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func TestRecordEventIndustrialScope(t *testing.T) {
	learner := New()
	for _, protocol := range []string{"http", "dns", "tls", "ssh", "smb", "ntp", "snmp", "rdp", "ics", "tcp", "udp",
		"iec104", "s7comm", "s7", "mms", "iec61850", "goose", "bacnet", "opcua", ""} {
		learner.RecordEvent("192.0.2.1", "192.0.2.2", dpi.Event{Proto: protocol, Kind: "request"})
	}
	if len(learner.Profiles()) != 0 || len(learner.GenerateRules()) != 0 {
		t.Fatal("non-learnable protocols created profiles or rules")
	}
	events := []dpi.Event{
		{Proto: "modbus", Kind: "request", Attributes: map[string]any{"function_code": uint8(6), "unit_id": uint8(1), "address": uint16(10), "is_write": true}},
		{Proto: "dnp3", Kind: "request", Attributes: map[string]any{"function_code": uint8(1), "function_name": "read", "object_groups": "60,60,60", "is_write": false}},
		{Proto: "cip", Kind: "request", Attributes: map[string]any{"service_code": uint8(0x4c), "service_name": "Read_Tag", "object_class": uint16(0x6b), "cip_path": "206b2401", "is_write": false}},
		{Proto: "cip", Kind: "request", Attributes: map[string]any{"service_code": uint8(0x4c), "service_name": "Template_Read", "object_class": uint16(0x6c), "cip_path": "206c2401", "is_write": false}},
	}
	for _, event := range events {
		learner.RecordEvent("192.0.2.1", "192.0.2.2", event)
	}
	if len(learner.Profiles()) != 3 || len(learner.GenerateRules()) != 3 {
		t.Fatal("kept learnable protocols were excluded")
	}

	generated := learner.GenerateRules()
	for _, rule := range generated {
		if rule.ICS.Direction != eventfields.KindRequest {
			t.Errorf("%s direction = %q, want request", rule.ICS.Protocol, rule.ICS.Direction)
		}
		switch rule.ICS.Protocol {
		case "dnp3":
			if rule.ID != "learned-dnp3-192.0.2.1-192.0.2.2-unone-fc01" {
				t.Errorf("DNP3 rule ID = %q", rule.ID)
			}
			if len(rule.ICS.Addresses) != 0 {
				t.Errorf("DNP3 generated addresses %v", rule.ICS.Addresses)
			}
			if len(rule.ICS.FunctionCode) != 1 || rule.ICS.FunctionCode[0] != 1 {
				t.Errorf("DNP3 function codes = %v, want only 1", rule.ICS.FunctionCode)
			}
			if rule.ICS.UnitID != nil {
				t.Errorf("DNP3 unexpectedly has Modbus unit ID %d", *rule.ICS.UnitID)
			}
		case "cip":
			if rule.ID != "learned-cip-192.0.2.1-192.0.2.2-unone-fc4c" {
				t.Errorf("CIP rule ID = %q", rule.ID)
			}
			if len(rule.ICS.Addresses) != 0 {
				t.Errorf("CIP generated addresses %v", rule.ICS.Addresses)
			}
			if len(rule.ICS.FunctionCode) != 1 || rule.ICS.FunctionCode[0] != 0x4c {
				t.Errorf("CIP function codes = %v, want only service 0x4c", rule.ICS.FunctionCode)
			}
			if rule.ICS.UnitID != nil {
				t.Errorf("CIP unexpectedly has Modbus unit ID %d", *rule.ICS.UnitID)
			}
			if len(rule.ICS.ObjectClasses) != 2 || rule.ICS.ObjectClasses[0] != 0x6b || rule.ICS.ObjectClasses[1] != 0x6c {
				t.Errorf("CIP object classes = %v, want only observed classes [0x6b 0x6c]", rule.ICS.ObjectClasses)
			}
		}
	}
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, generated...)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("generated rules fail config validation: %v", err)
	}
}

func TestLearnerAcceptsOnlySupportedRequests(t *testing.T) {
	validAttributes := map[string]map[string]any{
		"modbus": {"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(10), "quantity": uint16(1)},
		"dnp3":   {"function_code": uint8(1), "function_name": "read"},
		"cip":    {"service_code": uint8(0x4c), "service_name": "Read_Tag", "is_write": false},
	}
	for _, protocol := range []string{"modbus", "dnp3", "cip"} {
		t.Run(protocol, func(t *testing.T) {
			for _, kind := range []string{"response", "exception", "malformed", "unsupported", "session"} {
				learner := New()
				learner.RecordEvent("192.0.2.1", "192.0.2.2", dpi.Event{
					Proto: protocol, Kind: kind, Attributes: validAttributes[protocol],
				})
				if len(learner.Profiles()) != 0 || len(learner.GenerateRules()) != 0 {
					t.Errorf("%s event created a learned profile or rule: %+v", kind, learner.GenerateRules())
				}
			}
		})
	}

	for _, event := range []dpi.Event{
		{Proto: "dnp3", Kind: "restart", Attributes: map[string]any{"function_code": uint8(13)}},
		{Proto: "dnp3", Kind: "control", Attributes: map[string]any{"function_code": uint8(18)}},
	} {
		learner := New()
		learner.RecordEvent("192.0.2.1", "192.0.2.2", event)
		generated := learner.GenerateRules()
		if len(generated) != 1 {
			t.Errorf("DNP3 %s request did not generate a scoped rule: %+v", event.Kind, generated)
			continue
		}
		if generated[0].ICS.Direction != eventfields.KindRequest || len(generated[0].ICS.FunctionCode) != 1 ||
			generated[0].ICS.FunctionCode[0] != event.Attributes["function_code"] {
			t.Errorf("DNP3 %s rule predicate = %+v", event.Kind, generated[0].ICS)
		}
	}

	for _, event := range []dpi.Event{
		{Proto: "dnp3", Kind: eventfields.KindRequest, Attributes: map[string]any{"function_code": uint8(34)}},
		{Proto: "cip", Kind: eventfields.KindRequest, Attributes: map[string]any{"service_code": uint8(0x7f)}},
		{Proto: "cip", Kind: eventfields.KindRequest, Attributes: map[string]any{"service_code": uint8(0x4c), "service_name": "Unknown(0x4C)", "is_write": false}},
		{Proto: "cip", Kind: eventfields.KindRequest, Attributes: map[string]any{"service_code": uint8(0x4c), "service_name": "Read_Tag"}},
		{Proto: "cip", Kind: eventfields.KindRequest, Attributes: map[string]any{"service_code": uint8(0x4c), "is_write": false}},
	} {
		learner := New()
		learner.RecordEvent("192.0.2.1", "192.0.2.2", event)
		if len(learner.GenerateRules()) != 0 {
			t.Errorf("unsupported %s request generated a rule: %+v", event.Proto, learner.GenerateRules())
		}
	}
}
