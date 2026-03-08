// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package export

import (
	"fmt"
	"strings"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

// Exporter formats DPI events and writes them to a configured sink.
type Exporter struct {
	mu        sync.Mutex
	formatter Formatter
	sink      Sink
	filter    string // "all", "ics-only", "alerts-only"
}

// New creates an Exporter with the specified format and target.
//
// format: "cef", "json", or "syslog"
// target: a URL such as "file:///var/log/export.log", "udp://host:514", or "tcp://host:514"
func New(format string, target string) (*Exporter, error) {
	f, err := NewFormatter(format)
	if err != nil {
		return nil, err
	}
	s, err := NewSink(target)
	if err != nil {
		return nil, err
	}
	return &Exporter{
		formatter: f,
		sink:      s,
		filter:    "all",
	}, nil
}

// NewWithFilter creates an Exporter with a filter applied.
func NewWithFilter(format string, target string, filter string) (*Exporter, error) {
	e, err := New(format, target)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filter) {
	case "ics-only", "alerts-only", "all", "":
		e.filter = strings.ToLower(filter)
	default:
		return nil, fmt.Errorf("unknown export filter: %q", filter)
	}
	if e.filter == "" {
		e.filter = "all"
	}
	return e, nil
}

// NewFromParts creates an Exporter from pre-built formatter and sink (useful for testing).
func NewFromParts(formatter Formatter, sink Sink, filter string) *Exporter {
	if filter == "" {
		filter = "all"
	}
	return &Exporter{
		formatter: formatter,
		sink:      sink,
		filter:    filter,
	}
}

// Export formats and writes an event. Events that do not match the configured
// filter are silently discarded.
func (e *Exporter) Export(ev dpi.Event) error {
	if e == nil {
		return nil
	}
	if !e.matchesFilter(ev) {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := e.formatter.Format(ev)
	if err != nil {
		return fmt.Errorf("format event: %w", err)
	}
	if err := e.sink.Write(data); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

func (e *Exporter) matchesFilter(ev dpi.Event) bool {
	switch e.filter {
	case "ics-only":
		proto := strings.ToLower(ev.Proto)
		return proto == "modbus" || proto == "dnp3" || proto == "opcua" ||
			proto == "s7" || proto == "bacnet" || proto == "enip" ||
			proto == "ics"
	case "alerts-only":
		return strings.Contains(strings.ToLower(ev.Kind), "alert")
	default:
		return true
	}
}

// Close releases resources held by the exporter's sink.
func (e *Exporter) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sink.Close()
}
