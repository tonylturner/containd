// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func testEvent() dpi.Event {
	return dpi.Event{
		FlowID:    "flow-123",
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		Attributes: map[string]any{
			"function_code": 3,
			"unit_id":       1,
			"src":           "192.168.1.10",
			"dst":           "192.168.1.20",
		},
	}
}

func TestCEFFormatterValid(t *testing.T) {
	f := &CEFFormatter{}
	ev := testEvent()
	data, err := f.Format(ev)
	if err != nil {
		t.Fatalf("CEF format error: %v", err)
	}
	s := string(data)
	// Check CEF header fields.
	if !strings.HasPrefix(s, "CEF:0|containd|NGFW|1.0|") {
		t.Fatalf("CEF header mismatch: %s", s)
	}
	// Check signature ID (proto.kind).
	if !strings.Contains(s, "modbus.request") {
		t.Fatalf("expected signatureId 'modbus.request' in: %s", s)
	}
	// Check severity = 1 (read).
	parts := strings.SplitN(s, "|", 8)
	if len(parts) < 7 {
		t.Fatalf("expected at least 7 pipe-delimited parts, got %d: %s", len(parts), s)
	}
	if parts[6] != "1" {
		t.Fatalf("expected severity 1 for read, got %s", parts[6])
	}
	// Check extensions.
	if !strings.Contains(s, "cs1=3") {
		t.Fatalf("expected cs1=3 (function_code) in: %s", s)
	}
	if !strings.Contains(s, "cs2=1") {
		t.Fatalf("expected cs2=1 (unit_id) in: %s", s)
	}
	if !strings.Contains(s, "src=192.168.1.10") {
		t.Fatalf("expected src in: %s", s)
	}
}

func TestCEFSeverityLevels(t *testing.T) {
	f := &CEFFormatter{}
	cases := []struct {
		kind     string
		severity string
	}{
		{"read_register", "1"},
		{"write_coil", "3"},
		{"control_cmd", "5"},
		{"alert_overflow", "7"},
	}
	for _, tc := range cases {
		ev := dpi.Event{Proto: "modbus", Kind: tc.kind, Timestamp: time.Now()}
		data, err := f.Format(ev)
		if err != nil {
			t.Fatalf("format %s: %v", tc.kind, err)
		}
		parts := strings.SplitN(string(data), "|", 8)
		if len(parts) < 7 {
			t.Fatalf("not enough parts for %s", tc.kind)
		}
		if parts[6] != tc.severity {
			t.Errorf("kind=%s: expected severity %s, got %s", tc.kind, tc.severity, parts[6])
		}
	}
}

func TestJSONFormatterValid(t *testing.T) {
	f := &JSONFormatter{}
	ev := testEvent()
	data, err := f.Format(ev)
	if err != nil {
		t.Fatalf("JSON format error: %v", err)
	}
	// Should be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\ndata: %s", err, string(data))
	}
	if parsed["proto"] != "modbus" {
		t.Fatalf("expected proto=modbus, got %v", parsed["proto"])
	}
	if parsed["kind"] != "request" {
		t.Fatalf("expected kind=request, got %v", parsed["kind"])
	}
	// Should end with newline.
	if data[len(data)-1] != '\n' {
		t.Fatal("expected trailing newline")
	}
}

func TestSyslogFormatterWraps(t *testing.T) {
	inner := &CEFFormatter{}
	f := NewSyslogFormatter(inner, "myhost")
	ev := testEvent()
	data, err := f.Format(ev)
	if err != nil {
		t.Fatalf("Syslog format error: %v", err)
	}
	s := string(data)
	// RFC 5424 starts with <PRI>VERSION.
	if !strings.HasPrefix(s, "<14>1 ") {
		t.Fatalf("expected RFC 5424 header, got: %s", s[:20])
	}
	if !strings.Contains(s, "myhost") {
		t.Fatalf("expected hostname in syslog output: %s", s)
	}
	if !strings.Contains(s, "CEF:0|") {
		t.Fatalf("expected CEF payload in syslog output: %s", s)
	}
}

func TestFileSinkWritesCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-export.log")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("new file sink: %v", err)
	}

	if err := sink.Write([]byte("line1")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.Write([]byte("line2\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "line1") || !strings.Contains(content, "line2") {
		t.Fatalf("unexpected file content: %s", content)
	}
}

func TestNewSinkParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sink-test.log")
	sink, err := NewSink("file://" + path)
	if err != nil {
		t.Fatalf("new sink file: %v", err)
	}
	_ = sink.Close()

	// Unknown scheme.
	_, err = NewSink("ftp://foo:21")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestExporterEndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "e2e-export.log")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("new file sink: %v", err)
	}
	formatter := &JSONFormatter{}
	exporter := NewFromParts(formatter, sink, "all")

	ev := testEvent()
	if err := exporter.Export(ev); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON in exported file: %v\ndata: %s", err, string(data))
	}
	if parsed["proto"] != "modbus" {
		t.Fatalf("expected proto=modbus in output, got %v", parsed["proto"])
	}
}

func TestExporterFilterICSOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filter-test.log")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("new file sink: %v", err)
	}
	formatter := &JSONFormatter{}
	exporter := NewFromParts(formatter, sink, "ics-only")

	// ICS event should pass.
	icsEv := dpi.Event{Proto: "modbus", Kind: "request", Timestamp: time.Now()}
	if err := exporter.Export(icsEv); err != nil {
		t.Fatalf("export ics: %v", err)
	}
	// Non-ICS event should be filtered.
	httpEv := dpi.Event{Proto: "http", Kind: "request", Timestamp: time.Now()}
	if err := exporter.Export(httpEv); err != nil {
		t.Fatalf("export http: %v", err)
	}
	_ = exporter.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (ICS only), got %d: %s", len(lines), string(data))
	}
}

func TestNewFormatterValid(t *testing.T) {
	for _, name := range []string{"cef", "json", "syslog"} {
		f, err := NewFormatter(name)
		if err != nil {
			t.Fatalf("NewFormatter(%q): %v", name, err)
		}
		if f == nil {
			t.Fatalf("NewFormatter(%q) returned nil", name)
		}
	}
	_, err := NewFormatter("unknown")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}
