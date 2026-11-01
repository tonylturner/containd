// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package evidence holds the wire types that report whether containd's
// evidence is complete: local audit persistence and syslog forwarding.
// Producers (audit store, syslog manager) fill them; the management API,
// UI and CLI read them. It has no behaviour.
package evidence

import "time"

// State is the condition of one evidence path.
type State string

const (
	// StateOK means the last attempt succeeded and nothing is known lost.
	StateOK State = "ok"
	// StateDegraded means the most recent attempt failed.
	StateDegraded State = "degraded"
	// StateRecovered means the path works again after a recorded failure or
	// loss since process start; the counters keep the history.
	StateRecovered State = "recovered"
	// StateUnknown means the producer cannot be asked.
	StateUnknown State = "unknown"
)

// Source names a stream that syslog forwards.
type Source string

const (
	SourceEngine   Source = "engine"
	SourceServices Source = "services"
	SourceAudit    Source = "audit"
)

// AuditStatus describes local audit persistence since process start.
type AuditStatus struct {
	State         State      `json:"state"`
	Failures      uint64     `json:"failures"`
	LastFailureAt *time.Time `json:"lastFailureAt,omitempty"`
	// LastError is sanitized: no secrets, paths or record details.
	LastError     string     `json:"lastError,omitempty"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
}

// ForwardStatus describes one source to one syslog destination.
type ForwardStatus struct {
	Destination string `json:"destination"` // "proto://host:port"
	Source      Source `json:"source"`
	State       State  `json:"state"`
	// SentThrough is the opaque source offset delivered through, as a
	// decimal string so 64-bit values stay exact in JavaScript.
	SentThrough string `json:"sentThrough,omitempty"`
	// Backlog is records retained but not yet delivered.
	Backlog uint64 `json:"backlog"`
	// Lost is records that left retention or were dropped before delivery.
	Lost          uint64     `json:"lost"`
	LastError     string     `json:"lastError,omitempty"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
}

// Status is the authenticated evidence report.
type Status struct {
	Audit      AuditStatus     `json:"audit"`
	Forwarding []ForwardStatus `json:"forwarding"`
}

// AuditReporter is implemented by the observed audit store.
type AuditReporter interface {
	AuditStatus() AuditStatus
}

// ForwardReporter is implemented by the syslog manager.
type ForwardReporter interface {
	ForwardStatus() []ForwardStatus
}
