// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestParseSnortBasicAlert(t *testing.T) {
	line := `alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Snort HTTP test"; content:"GET"; sid:1000; rev:1; classtype:web-application-attack;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "snort-1000" {
		t.Fatalf("expected ID snort-1000, got %s", r.ID)
	}
	if r.SourceFormat != "snort" {
		t.Fatalf("expected sourceFormat snort, got %s", r.SourceFormat)
	}
	if r.Proto != "http" {
		t.Fatalf("expected proto http (port 80), got %s", r.Proto)
	}
	if r.Severity != "high" {
		t.Fatalf("expected severity high (from web-application-attack), got %s", r.Severity)
	}
}

func TestParseSnortIDPrefix(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Prefix test"; sid:999; rev:1;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "snort-999" {
		t.Fatalf("expected snort- prefix, got %s", r.ID)
	}
}

func TestParseSnortActivatedBy(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Dynamic rule"; sid:500; rev:1; activated_by:100; count:50;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Labels["activated_by"] != "100" {
		t.Fatalf("expected activated_by=100, got %s", r.Labels["activated_by"])
	}
	if r.Labels["count"] != "50" {
		t.Fatalf("expected count=50, got %s", r.Labels["count"])
	}
}

func TestParseSnortTag(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Tag test"; sid:501; rev:1; tag:session,300,seconds;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Labels["tag"] != "session,300,seconds" {
		t.Fatalf("expected tag value, got %s", r.Labels["tag"])
	}
}

func TestParseSnortCommentAndBlank(t *testing.T) {
	r, err := ParseSnortLine("# Snort comment")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "" {
		t.Fatalf("expected empty rule for comment")
	}

	r, err = ParseSnortLine("   ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "" {
		t.Fatalf("expected empty rule for blank line")
	}
}

func TestParseSnortMalformed(t *testing.T) {
	_, err := ParseSnortLine("alert tcp garbage")
	if err == nil {
		t.Fatal("expected error for malformed rule")
	}
}

func TestParseSnortContentWithModifiers(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Content test"; content:"|DE AD|"; depth:4; offset:2; content:"follow"; distance:0; within:20; nocase; sid:600; rev:1;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.ContentMatches) != 2 {
		t.Fatalf("expected 2 content matches, got %d", len(r.ContentMatches))
	}
	// First: hex content with depth/offset.
	cm0 := r.ContentMatches[0]
	if !cm0.IsHex || cm0.Pattern != "DE AD" || cm0.Depth != 4 || cm0.Offset != 2 {
		t.Fatalf("first content mismatch: %+v", cm0)
	}
	// Second: string content with distance/within/nocase.
	cm1 := r.ContentMatches[1]
	if cm1.IsHex || cm1.Pattern != "follow" || cm1.Distance != 0 || cm1.Within != 20 || !cm1.Nocase {
		t.Fatalf("second content mismatch: %+v", cm1)
	}
}

func TestConvertSnortFile(t *testing.T) {
	data := []byte(`# Snort rules
alert tcp any any -> any 502 (msg:"Modbus"; sid:10; rev:1;)
alert udp any any -> any 20000 (msg:"DNP3"; sid:11; rev:1;)
`)
	rules, err := ConvertSnortFile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].SourceFormat != "snort" || rules[1].SourceFormat != "snort" {
		t.Fatalf("expected snort sourceFormat")
	}
	if rules[0].Proto != "modbus" || rules[1].Proto != "dnp3" {
		t.Fatalf("unexpected protos: %s, %s", rules[0].Proto, rules[1].Proto)
	}
}

func TestConvertSnortFiles(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.rules")
	if err := os.WriteFile(f, []byte(`alert tcp any any -> any any (msg:"X"; sid:1; rev:1;)`), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := ConvertSnortFiles([]string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "snort-1" {
		t.Fatalf("unexpected result: %+v", rules)
	}
}

func TestParseSnortDropAction(t *testing.T) {
	line := `drop tcp any any -> any any (msg:"Drop rule"; sid:700; rev:1; priority:2;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Action != "drop" {
		t.Fatalf("expected action drop, got %s", r.Action)
	}
	if r.Severity != "high" {
		t.Fatalf("expected severity high (priority 2), got %s", r.Severity)
	}
}

func TestParseSnortNoSIDFallback(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"No SID"; rev:1;)`
	r, err := ParseSnortLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "snort-no-sid" {
		t.Fatalf("expected fallback ID snort-no-sid, got %s", r.ID)
	}
}

func TestParseSnort3ContentModifiers(t *testing.T) {
	line := `alert tcp any any -> any any (msg:"Snort 3"; content:!"a\";b,c\;d\\", nocase, depth 30, offset 2; content:"|DE AD BE EF|", distance -3, within 40; content:"tail", distance 3; nocase; depth:10; sid:900;)`
	rule, err := ParseSnortLine(line)
	if err != nil {
		t.Fatal(err)
	}
	want := []config.ContentMatch{
		{Pattern: "a\";b,c;d\\", Negate: true, Nocase: true, Depth: 30, Offset: 2},
		{Pattern: "DE AD BE EF", IsHex: true, Distance: -3, Within: 40},
		{Pattern: "tail", Distance: 3, Nocase: true, Depth: 10},
	}
	if !reflect.DeepEqual(rule.ContentMatches, want) {
		t.Fatalf("got %#v, want %#v", rule.ContentMatches, want)
	}
}

func TestSnort3UnknownContentModifiers(t *testing.T) {
	commaForm := `alert tcp any any -> any any (content:"abc", fast_pattern, fast_pattern_offset 2, future_modifier 7, nocase; sid:901;)`
	separateForm := `alert tcp any any -> any any (content:"abc"; fast_pattern; fast_pattern_offset:2; future_modifier:7; nocase; sid:901;)`
	commaRule, err := ParseSnortLine(commaForm)
	if err != nil {
		t.Fatal(err)
	}
	separateRule, err := ParseSnortLine(separateForm)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commaRule.ContentMatches, separateRule.ContentMatches) {
		t.Fatalf("content differs: %#v vs %#v", commaRule.ContentMatches, separateRule.ContentMatches)
	}
	wantNotes := []string{
		`keyword "fast_pattern" not fully mapped`,
		`keyword "fast_pattern_offset" not fully mapped`,
		`keyword "future_modifier" not fully mapped`,
		`keyword "nocase" not fully mapped`,
		`keyword "content" not fully mapped`,
	}
	if !reflect.DeepEqual(commaRule.ConversionNotes, separateRule.ConversionNotes) ||
		!reflect.DeepEqual(commaRule.ConversionNotes, wantNotes) {
		t.Fatalf("conversion notes differ: comma=%v separate=%v want=%v",
			commaRule.ConversionNotes, separateRule.ConversionNotes, wantNotes)
	}
	if commaRule.Labels["evaluable"] != "false" || commaRule.RawSource != commaForm {
		t.Fatalf("unknown modifiers must mark rule non-evaluable and retain raw source: %+v", commaRule)
	}
}

func TestSnort3ContentModifiersAreSnortOnly(t *testing.T) {
	line := `alert tcp any any -> any any (content:"abc,def", nocase, depth 10; sid:902;)`
	snort, err := ParseSnortLine(line)
	if err != nil {
		t.Fatal(err)
	}
	suricata, err := ParseSuricataLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if len(snort.ContentMatches) != 1 || snort.ContentMatches[0].Pattern != "abc,def" ||
		!snort.ContentMatches[0].Nocase || snort.ContentMatches[0].Depth != 10 {
		t.Fatalf("Snort 3 modifiers not parsed: %#v", snort.ContentMatches)
	}
	if len(suricata.ContentMatches) != 1 || suricata.ContentMatches[0].Nocase ||
		suricata.ContentMatches[0].Depth != 0 || suricata.Labels["evaluable"] != "false" {
		t.Fatalf("Suricata must not interpret Snort 3 modifiers: %+v", suricata)
	}
}
