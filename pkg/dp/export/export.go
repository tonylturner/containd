// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package export

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// Formatter converts a DPI event into a wire-format byte slice.
type Formatter interface {
	Format(ev dpi.Event) ([]byte, error)
}

// CEFFormatter produces ArcSight Common Event Format strings.
type CEFFormatter struct{}

// severityFromKind maps event kinds to CEF severity levels.
func severityFromKind(kind string) int {
	lower := strings.ToLower(kind)
	switch {
	case strings.Contains(lower, "alert"):
		return 7
	case strings.Contains(lower, "control"):
		return 5
	case strings.Contains(lower, "write"):
		return 3
	default:
		return 1
	}
}

// descriptiveName builds a human-readable name from protocol and kind.
func descriptiveName(proto, kind string) string {
	if proto == "" && kind == "" {
		return "DPI Event"
	}
	if proto == "" {
		return kind
	}
	if kind == "" {
		return proto
	}
	return proto + " " + kind
}

// Format produces a CEF:0 formatted line.
//
// Format: CEF:0|containd|NGFW|1.0|<signatureId>|<name>|<severity>|<extensions>
func (f *CEFFormatter) Format(ev dpi.Event) ([]byte, error) {
	sigID := ev.Proto + "." + ev.Kind
	name := descriptiveName(ev.Proto, ev.Kind)
	severity := severityFromKind(ev.Kind)

	var ext []string
	ext = append(ext, fmt.Sprintf("rt=%d", ev.Timestamp.UnixMilli()))
	if ev.FlowID != "" {
		ext = append(ext, "flowId="+cefEscape(ev.FlowID))
	}
	ext = append(ext, "proto="+cefEscape(ev.Proto))

	// Map well-known attributes to CEF custom string fields.
	if ev.Attributes != nil {
		if v, ok := ev.Attributes["function_code"]; ok {
			ext = append(ext, fmt.Sprintf("cs1=%v", v))
			ext = append(ext, "cs1Label=function_code")
		}
		if v, ok := ev.Attributes["unit_id"]; ok {
			ext = append(ext, fmt.Sprintf("cs2=%v", v))
			ext = append(ext, "cs2Label=unit_id")
		}
		if v, ok := ev.Attributes["src"]; ok {
			ext = append(ext, fmt.Sprintf("src=%v", v))
		}
		if v, ok := ev.Attributes["dst"]; ok {
			ext = append(ext, fmt.Sprintf("dst=%v", v))
		}
	}

	line := fmt.Sprintf("CEF:0|containd|NGFW|1.0|%s|%s|%d|%s",
		cefEscape(sigID),
		cefEscape(name),
		severity,
		strings.Join(ext, " "),
	)
	return []byte(line), nil
}

// cefEscape escapes pipe and backslash characters for CEF fields.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// JSONFormatter produces JSON-lines output (one JSON object per line).
type JSONFormatter struct{}

type jsonEvent struct {
	Timestamp  string         `json:"timestamp"`
	FlowID     string         `json:"flowId,omitempty"`
	Proto      string         `json:"proto"`
	Kind       string         `json:"kind"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

func (f *JSONFormatter) Format(ev dpi.Event) ([]byte, error) {
	je := jsonEvent{
		Timestamp:  ev.Timestamp.UTC().Format(time.RFC3339Nano),
		FlowID:     ev.FlowID,
		Proto:      ev.Proto,
		Kind:       ev.Kind,
		Attributes: ev.Attributes,
	}
	data, err := json.Marshal(je)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}
	return append(data, '\n'), nil
}

// SyslogFormatter wraps another Formatter in an RFC 5424 syslog envelope.
type SyslogFormatter struct {
	Inner    Formatter
	Hostname string
	AppName  string
}

// NewSyslogFormatter creates a SyslogFormatter wrapping the given inner formatter.
func NewSyslogFormatter(inner Formatter, hostname string) *SyslogFormatter {
	if hostname == "" {
		hostname = "containd"
	}
	return &SyslogFormatter{
		Inner:    inner,
		Hostname: hostname,
		AppName:  "containd-dpi",
	}
}

// Format produces an RFC 5424 syslog message wrapping the inner format.
//
// <14>1 <timestamp> <hostname> <appname> - - - <inner message>
func (f *SyslogFormatter) Format(ev dpi.Event) ([]byte, error) {
	inner, err := f.Inner.Format(ev)
	if err != nil {
		return nil, err
	}
	// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	// PRI 14 = facility 1 (user), severity 6 (informational)
	ts := ev.Timestamp.UTC().Format(time.RFC3339)
	header := fmt.Sprintf("<14>1 %s %s %s - - - ", ts, f.Hostname, f.AppName)
	msg := append([]byte(header), inner...)
	return msg, nil
}

// NewFormatter creates a Formatter by name.
func NewFormatter(format string) (Formatter, error) {
	switch strings.ToLower(format) {
	case "cef":
		return &CEFFormatter{}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "syslog":
		// Default syslog wraps CEF.
		return NewSyslogFormatter(&CEFFormatter{}, ""), nil
	default:
		return nil, fmt.Errorf("unknown export format: %q", format)
	}
}
