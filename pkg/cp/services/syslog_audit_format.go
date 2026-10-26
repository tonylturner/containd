// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tonylturner/containd/pkg/cp/audit"
)

// Forwarded audit fields are bounded so one record fits a syslog datagram.
const (
	auditDetailLimit = 1024
	auditTargetLimit = 256
	auditFieldLimit  = 128
)

// RFC 5424 facility 13 is "log audit".
const auditFacility = 13

// auditJSONMessage is the JSON wire form of a forwarded audit record. kind
// "audit" separates it from forwarded events.
type auditJSONMessage struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
	audit.Record
}

func formatAudit(r audit.Record, format, host string) string {
	r = boundAuditRecord(r)
	if format == "json" {
		b, _ := json.Marshal(auditJSONMessage{Kind: "audit", Host: host, Record: r})
		return string(b)
	}
	return formatAuditRFC5424(r, host)
}

// formatAuditRFC5424 renders MSGID "audit" with the record in the
// audit@47450 structured-data element and a readable summary as MSG.
func formatAuditRFC5424(r audit.Record, host string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 %s %s containd - audit [audit@47450", auditFacility*8+auditSeverity(r.Result), r.Timestamp.UTC().Format(time.RFC3339), host)
	fmt.Fprintf(&b, ` id="%d"`, r.ID)
	for _, p := range []struct{ name, value string }{
		{"actor", r.Actor},
		{"source", r.Source},
		{"action", r.Action},
		{"target", r.Target},
		{"result", r.Result},
		{"detail", r.Detail},
	} {
		fmt.Fprintf(&b, ` %s="%s"`, p.name, escapeSyslogText(p.value, true))
	}
	b.WriteString("] ")
	b.WriteString(escapeSyslogText(fmt.Sprintf("%s %s %s: %s", r.Actor, r.Action, r.Target, r.Result), false))
	return b.String()
}

// auditSeverity is notice (5) for a successful or informational record and
// warning (4) for anything else, such as denied, failure or fault.
func auditSeverity(result string) int {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "", "success", "ok", "requested":
		return 5
	default:
		return 4
	}
}

func boundAuditRecord(r audit.Record) audit.Record {
	r.Actor = truncateUTF8(r.Actor, auditFieldLimit)
	r.Source = truncateUTF8(r.Source, auditFieldLimit)
	r.Action = truncateUTF8(r.Action, auditFieldLimit)
	r.Result = truncateUTF8(r.Result, auditFieldLimit)
	r.Target = truncateUTF8(r.Target, auditTargetLimit)
	r.Detail = truncateUTF8(r.Detail, auditDetailLimit)
	return r
}

// truncateUTF8 returns valid UTF-8 of at most limit bytes, marking a cut with
// an ellipsis.
func truncateUTF8(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}
	const mark = "…"
	cut := limit - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}

// escapeSyslogText escapes control characters so a value cannot break
// newline framing or forge a second message. In a structured-data value it
// also escapes '"', '\' and ']' as RFC 5424 section 6.3.3 requires.
func escapeSyslogText(s string, paramValue bool) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		case paramValue && (r == '"' || r == '\\' || r == ']'):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
