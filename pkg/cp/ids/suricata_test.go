// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuricataBasicAlertTCP(t *testing.T) {
	line := `alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET MALWARE Possible Malicious SSL Cert"; content:"|16 03|"; depth:2; sid:2028000; rev:3; classtype:trojan-activity; reference:url,example.com;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "suricata-2028000" {
		t.Fatalf("expected ID suricata-2028000, got %s", r.ID)
	}
	if r.SourceFormat != "suricata" {
		t.Fatalf("expected sourceFormat suricata, got %s", r.SourceFormat)
	}
	if r.Action != "alert" {
		t.Fatalf("expected action alert, got %s", r.Action)
	}
	if r.Title != "ET MALWARE Possible Malicious SSL Cert" {
		t.Fatalf("unexpected title: %s", r.Title)
	}
	if r.Message != r.Title {
		t.Fatalf("message should match title")
	}
	if r.SrcAddr != "$HOME_NET" || r.DstAddr != "$EXTERNAL_NET" {
		t.Fatalf("unexpected addresses: src=%s dst=%s", r.SrcAddr, r.DstAddr)
	}
	if r.SrcPort != "any" || r.DstPort != "443" {
		t.Fatalf("unexpected ports: src=%s dst=%s", r.SrcPort, r.DstPort)
	}
	if r.Proto != "tls" {
		t.Fatalf("expected proto tls (from port 443), got %s", r.Proto)
	}
	if r.Labels["classtype"] != "trojan-activity" {
		t.Fatalf("expected classtype trojan-activity, got %s", r.Labels["classtype"])
	}
	if r.Labels["rev"] != "3" {
		t.Fatalf("expected rev 3, got %s", r.Labels["rev"])
	}
	if len(r.References) != 1 || r.References[0] != "url,example.com" {
		t.Fatalf("unexpected references: %v", r.References)
	}
	if r.RawSource != line {
		t.Fatalf("RawSource mismatch")
	}
	if r.Severity != "high" {
		t.Fatalf("expected severity high (from classtype trojan-activity), got %s", r.Severity)
	}
}

func TestParseSuricataDropUDP(t *testing.T) {
	line := `drop udp any any -> any 53 (msg:"Block DNS query"; sid:1000001; rev:1; priority:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Action != "drop" {
		t.Fatalf("expected action drop, got %s", r.Action)
	}
	if r.Proto != "dns" {
		t.Fatalf("expected proto dns (from port 53), got %s", r.Proto)
	}
	if r.Severity != "critical" {
		t.Fatalf("expected severity critical (priority 1), got %s", r.Severity)
	}
}

func TestParseSuricataAlertHTTP(t *testing.T) {
	line := `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Test"; content:"GET"; http_method; content:"/malware"; http_uri; sid:9999; rev:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Proto != "http" {
		t.Fatalf("expected proto http, got %s", r.Proto)
	}
	// Should have When conditions from http_method and http_uri.
	if len(r.When.All) != 2 {
		t.Fatalf("expected 2 When conditions, got %d: %+v", len(r.When.All), r.When)
	}
	if r.When.All[0].Field != "attr.http_method" || r.When.All[0].Value != "GET" {
		t.Fatalf("unexpected first When condition: %+v", r.When.All[0])
	}
	if r.When.All[1].Field != "attr.http_uri" || r.When.All[1].Value != "/malware" {
		t.Fatalf("unexpected second When condition: %+v", r.When.All[1])
	}
}

func TestParseSuricataContentHex(t *testing.T) {
	line := `alert tcp any any -> any 502 (msg:"Modbus write coil"; content:"|00 05|"; depth:2; sid:3000; rev:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Proto != "modbus" {
		t.Fatalf("expected proto modbus, got %s", r.Proto)
	}
	if len(r.ContentMatches) != 1 {
		t.Fatalf("expected 1 content match, got %d", len(r.ContentMatches))
	}
	cm := r.ContentMatches[0]
	if !cm.IsHex {
		t.Fatal("expected IsHex=true")
	}
	if cm.Pattern != "00 05" {
		t.Fatalf("expected hex pattern '00 05', got %q", cm.Pattern)
	}
	if cm.Depth != 2 {
		t.Fatalf("expected depth 2, got %d", cm.Depth)
	}
}

func TestParseSuricataMultipleContent(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Multi content"; content:"abc"; offset:5; within:10; content:"def"; distance:3; nocase; sid:4000; rev:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.ContentMatches) != 2 {
		t.Fatalf("expected 2 content matches, got %d", len(r.ContentMatches))
	}
	// First content: "abc" with offset:5, within:10.
	if r.ContentMatches[0].Pattern != "abc" || r.ContentMatches[0].Offset != 5 || r.ContentMatches[0].Within != 10 {
		t.Fatalf("first content mismatch: %+v", r.ContentMatches[0])
	}
	// Second content: "def" with distance:3, nocase.
	if r.ContentMatches[1].Pattern != "def" || r.ContentMatches[1].Distance != 3 || !r.ContentMatches[1].Nocase {
		t.Fatalf("second content mismatch: %+v", r.ContentMatches[1])
	}
}

func TestParseSuricataNegatedContent(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Negated"; content:!"badstuff"; sid:5000; rev:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.ContentMatches) != 1 {
		t.Fatalf("expected 1 content match, got %d", len(r.ContentMatches))
	}
	if !r.ContentMatches[0].Negate {
		t.Fatal("expected Negate=true")
	}
	if r.ContentMatches[0].Pattern != "badstuff" {
		t.Fatalf("expected pattern 'badstuff', got %q", r.ContentMatches[0].Pattern)
	}
}

func TestParseSuricataPrioritySeverity(t *testing.T) {
	tests := []struct {
		pri      string
		expected string
	}{
		{"1", "critical"},
		{"2", "high"},
		{"3", "medium"},
		{"4", "low"},
	}
	for _, tt := range tests {
		line := `alert tcp any any -> any any (msg:"pri test"; sid:6000; rev:1; priority:` + tt.pri + `;)`
		r, err := ParseSuricataLine(line)
		if err != nil {
			t.Fatalf("unexpected error for priority %s: %v", tt.pri, err)
		}
		if r.Severity != tt.expected {
			t.Fatalf("priority %s: expected severity %s, got %s", tt.pri, tt.expected, r.Severity)
		}
	}
}

func TestParseSuricataPortMapping(t *testing.T) {
	tests := []struct {
		port  string
		proto string
	}{
		{"502", "modbus"},
		{"44818", "enip"},
		{"20000", "dnp3"},
		{"4840", "opcua"},
		{"102", "s7comm"},
		{"47808", "bacnet"},
	}
	for _, tt := range tests {
		line := `alert tcp any any -> any ` + tt.port + ` (msg:"port test"; sid:7000; rev:1;)`
		r, err := ParseSuricataLine(line)
		if err != nil {
			t.Fatalf("unexpected error for port %s: %v", tt.port, err)
		}
		if r.Proto != tt.proto {
			t.Fatalf("port %s: expected proto %s, got %s", tt.port, tt.proto, r.Proto)
		}
	}
}

func TestParseSuricataMetadataCVE(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"CVE test"; sid:8000; rev:1; metadata:cve 2021-1234, mitre_attack_T1059;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.CVE) != 1 || r.CVE[0] != "2021-1234" {
		t.Fatalf("expected CVE [2021-1234], got %v", r.CVE)
	}
	if len(r.MITREAttackIDs) != 1 || r.MITREAttackIDs[0] != "mitre_attack_T1059" {
		t.Fatalf("expected MITRE [mitre_attack_T1059], got %v", r.MITREAttackIDs)
	}
}

func TestParseSuricataMultipleReferences(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"refs"; sid:8100; rev:1; reference:url,example.com; reference:cve,2022-9999;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.References) != 2 {
		t.Fatalf("expected 2 references, got %d", len(r.References))
	}
}

func TestParseSuricataBlankLine(t *testing.T) {
	r, err := ParseSuricataLine("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "" {
		t.Fatalf("expected empty rule for blank line, got ID=%s", r.ID)
	}
}

func TestParseSuricataCommentLine(t *testing.T) {
	r, err := ParseSuricataLine("# This is a comment")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "" {
		t.Fatalf("expected empty rule for comment, got ID=%s", r.ID)
	}
}

func TestParseSuricataMalformedNoParens(t *testing.T) {
	_, err := ParseSuricataLine("alert tcp any any -> any any msg:test;")
	if err == nil {
		t.Fatal("expected error for malformed rule")
	}
}

func TestParseSuricataMalformedShortHeader(t *testing.T) {
	_, err := ParseSuricataLine("alert tcp any (msg:\"x\"; sid:1;)")
	if err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestConvertSuricataFile(t *testing.T) {
	data := []byte(`# ET rules
alert tcp $HOME_NET any -> any 502 (msg:"Modbus read"; sid:100; rev:1;)

# Another comment
alert tcp any any -> any 44818 (msg:"EtherNet/IP scan"; sid:101; rev:1;)
`)
	rules, err := ConvertSuricataFile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID != "suricata-100" || rules[1].ID != "suricata-101" {
		t.Fatalf("unexpected IDs: %s, %s", rules[0].ID, rules[1].ID)
	}
}

func TestConvertSuricataFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.rules")
	f2 := filepath.Join(dir, "b.rules")
	if err := os.WriteFile(f1, []byte(`alert tcp any any -> any any (msg:"A"; sid:1; rev:1;)`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte(`alert tcp any any -> any any (msg:"B"; sid:2; rev:1;)`), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ConvertSuricataFiles([]string{f1, f2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestParseSuricataConversionNotes(t *testing.T) {
	// "pcre" is not a fully-mapped keyword; should generate a note.
	line := `alert tcp any any -> any any (msg:"pcre test"; sid:9000; rev:1; pcre:"/foo/i";)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, n := range r.ConversionNotes {
		if n == `keyword "pcre" not fully mapped` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected conversion note for pcre, got %v", r.ConversionNotes)
	}
}

func TestParseSuricataPassAction(t *testing.T) {
	line := `pass tcp any any -> any any (msg:"Allow rule"; sid:9500; rev:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Action != "pass" {
		t.Fatalf("expected action pass, got %s", r.Action)
	}
}

func TestParseSuricataNoSIDFallback(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"No SID rule"; rev:1;)`
	r, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "suricata-no-sid-rule" {
		t.Fatalf("expected fallback ID suricata-no-sid-rule, got %s", r.ID)
	}
}
