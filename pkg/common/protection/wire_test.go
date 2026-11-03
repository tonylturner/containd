// SPDX-License-Identifier: Apache-2.0

package protection

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMetadataIdentity(t *testing.T) {
	m := cleanInput().Current
	tests := []struct {
		name string
		edit func(*Metadata)
		want bool
	}{
		{"normal", func(*Metadata) {}, true},
		{"no boot", func(m *Metadata) { m.BootID = "" }, false},
		{"no attempt", func(m *Metadata) { m.ApplyID = "" }, false},
		{"no revision", func(m *Metadata) { m.RunningRevision = "" }, false},
		{"no mode", func(m *Metadata) { m.Mode = "" }, false},
		{"oversized token", func(m *Metadata) { m.ApplyID = ApplyID(strings.Repeat("a", MaxTokenLength+1)) }, false},
		{"control character", func(m *Metadata) { m.RunningRevision += "\n" }, false},
		{"recovery namespace in normal mode", func(m *Metadata) { m.RunningRevision = RecoveryRevision(m.BootID) }, false},
		{"recovery", func(m *Metadata) {
			m.Mode, m.RunningRevision = ModeRecovery, RecoveryRevision(m.BootID)
		}, true},
		{"stale recovery boot", func(m *Metadata) {
			m.Mode, m.RunningRevision = ModeRecovery, RecoveryRevision(m.BootID+"-old")
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := m
			tt.edit(&copy)
			if copy.Valid() != tt.want {
				t.Fatalf("Valid(%+v) != %v", copy, tt.want)
			}
		})
	}
}

func TestFrozenWire(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"admission", Admission{Metadata: cleanInput().Current},
			`{"bootId":"boot","applyId":"apply","runningRevision":"running","mode":"normal","previousApplyId":""}`},
		{"trust ack", Acknowledgement{Metadata: cleanInput().Current, Operation: OperationApply, TrustRevision: "none"},
			`{"bootId":"boot","applyId":"apply","runningRevision":"running","mode":"normal","operation":"apply","trustRevision":"none"}`},
		{"engine observation", cleanInput().Engine,
			`{"bootId":"boot","applyId":"apply","runningRevision":"running","mode":"normal","installed":{"bootId":"boot","applyId":"apply","runningRevision":"running","mode":"normal","operation":"apply"},"state":"protecting","observedAt":"1970-01-01T00:01:40Z"}`},
		{"unknown aggregate", Aggregate{State: StateUnknown, Subsystems: []SubsystemStatus{}},
			`{"desiredRevision":null,"appliedRevision":null,"protectingRevision":null,"ready":false,"state":"unknown","subsystems":[]}`},
		{"unknown subsystem", SubsystemStatus{OwnerOutcome: OwnerOutcome{
			Name: SubsystemTrust, Owner: OwnerEngine, DesiredRevision: "running",
			State: DeliveryUnknown, ObservedAt: time.Unix(100, 0).UTC(),
		}, Required: true, DesiredTrustRevision: "none"},
			`{"name":"trust","owner":"engine","desiredRevision":"running","operation":"","state":"unknown","acknowledged":null,"fault":null,"reason":"","attempt":0,"nextRetryAt":null,"observedAt":"1970-01-01T00:01:40Z","retryable":false,"required":true,"desiredTrustRevision":"none"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.in)
			if err != nil || string(got) != tt.want {
				t.Fatalf("wire = %s (%v), want %s", got, err, tt.want)
			}
		})
	}
	headers := []string{ApplyIDHeader, EngineBootIDHeader, RunningRevisionHeader, ApplyModeHeader, PreviousApplyIDHeader}
	want := []string{"X-Containd-Apply-Id", "X-Containd-Engine-Boot-Id", "X-Containd-Running-Revision", "X-Containd-Apply-Mode", "X-Containd-Previous-Apply-Id"}
	if !reflect.DeepEqual(headers, want) {
		t.Fatalf("headers changed: %v", headers)
	}
}

func TestFixedRequirements(t *testing.T) {
	base := Requirements(Selection{})
	names := make([]SubsystemName, 0, len(base))
	for _, row := range base {
		names = append(names, row.Name)
		wantOwner := OwnerEngine
		switch row.Name {
		case SubsystemOpenVPN, SubsystemForwardProxy, SubsystemReverseProxy,
			SubsystemAV, SubsystemDNS, SubsystemNTP, SubsystemSyslog:
			wantOwner = OwnerManagement
		}
		if row.Owner != wantOwner {
			t.Fatalf("owner(%s) = %s, want %s", row.Name, row.Owner, wantOwner)
		}
	}
	wantNames := []SubsystemName{
		"config", "nft", "interfaces", "routing", "forwarding", "iec-envelope",
		"scan-gate", "scanner", "trust", "openvpn", "wireguard",
		"forward-proxy", "reverse-proxy", "av", "dns", "ntp", "syslog", "dhcp",
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("table names changed: %v", names)
	}
	for _, row := range base {
		want := row.Name == SubsystemConfig || row.Name == SubsystemNFT ||
			row.Name == SubsystemInterfaces || row.Name == SubsystemRouting ||
			row.Name == SubsystemOpenVPN || row.Name == SubsystemWireGuard ||
			row.Name == SubsystemForwardProxy || row.Name == SubsystemReverseProxy
		if row.Required != want {
			t.Fatalf("required(%s) = %v, want %v", row.Name, row.Required, want)
		}
	}
	base[0].Required = false
	if !Requirements(Selection{})[0].Required {
		t.Fatal("caller mutated fixed table")
	}
	selected := Requirements(cleanInput().Selection)
	for _, row := range selected {
		want := row.Name != SubsystemAV && row.Name != SubsystemDNS &&
			row.Name != SubsystemNTP && row.Name != SubsystemSyslog && row.Name != SubsystemDHCP
		if row.Required != want {
			t.Fatalf("selected required(%s) = %v, want %v", row.Name, row.Required, want)
		}
	}
	in := cleanInput()
	in.Selection = Selection{}
	for i := range in.Outcomes {
		if !containsRequired(Requirements(in.Selection), in.Outcomes[i].Name) {
			in.Outcomes[i].State = DeliveryFailed
			in.Outcomes[i].Acknowledged = nil
		}
	}
	// Remove the no-longer-selected per-queue observation from this snapshot.
	in.Outcomes = in.Outcomes[:len(in.Outcomes)-1]
	if !Reduce(in).Ready {
		t.Fatal("unselected optional delivery gates")
	}
}

func containsRequired(rows []Requirement, name SubsystemName) bool {
	for _, row := range rows {
		if row.Name == name {
			return row.Required
		}
	}
	return false
}
