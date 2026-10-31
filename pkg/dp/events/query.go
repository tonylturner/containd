// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package events

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Query uses AND across filters. Kind is a comma-separated set of prefixes.
// Cursor is an exclusive (timestamp, ID) upper bound, not a durable log offset.
type Query struct {
	RuleID     string
	Mode       string
	EventID    uint64
	Detections bool
	Limit      int
	Session    string
	Flow       string
	Kind       string
	Protocol   string
	Decision   string
	Verdict    string
	APDU       string
	Category   string
	Since      time.Time
	Cursor     string
	before     Event
}

type Page struct {
	Events           []Event `json:"events"`
	NextCursor       string  `json:"nextCursor,omitempty"`
	HistoryTruncated bool    `json:"historyTruncated"`
	EngineError      string  `json:"engineError,omitempty"`
}

// ParseQuery is shared by management and engine to keep validation identical.
// Only-limit callers retain the legacy array contract and priority selection.
func ParseQuery(v url.Values) (q Query, filtered bool, err error) {
	q = Query{RuleID: v.Get("ruleId"), Mode: v.Get("mode"), Detections: v.Get("detections") == "1", Limit: 500, Session: v.Get("session"), Flow: v.Get("flow"), Kind: v.Get("kind"), Protocol: v.Get("protocol"), Decision: v.Get("decision"), Verdict: v.Get("verdict"), APDU: v.Get("apdu"), Category: v.Get("category"), Cursor: v.Get("cursor")}
	for _, k := range []string{"query", "ruleId", "mode", "id", "detections", "session", "flow", "kind", "protocol", "decision", "verdict", "apdu", "category", "since", "cursor"} {
		if v.Has(k) {
			filtered = true
		}
	}
	if raw := v.Get("id"); raw != "" {
		q.EventID, err = strconv.ParseUint(raw, 10, 64)
		if err != nil || q.EventID == 0 {
			return q, filtered, fmt.Errorf("id must be a positive uint64")
		}
	}
	if raw := v.Get("limit"); raw != "" {
		q.Limit, err = strconv.Atoi(raw)
		if err != nil || q.Limit < 1 || q.Limit > 5000 {
			return q, filtered, fmt.Errorf("limit must be 1..5000")
		}
	}
	if raw := v.Get("since"); raw != "" {
		q.Since, err = time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return q, filtered, fmt.Errorf("since must be RFC3339")
		}
	}
	if q.Mode != "" && q.Mode != "monitor" && q.Mode != "enforce" {
		return q, filtered, fmt.Errorf("mode must be monitor or enforce")
	}
	switch q.Category {
	case "", "all", "service", "proxy", "dpi", "firewall", "iec104":
	default:
		return q, filtered, fmt.Errorf("invalid category")
	}
	if q.Cursor != "" {
		q.before, err = decodeCursor(q.Cursor)
		if err != nil {
			return q, filtered, err
		}
	}
	return q, filtered, nil
}

func (q Query) Values() url.Values {
	v := url.Values{"query": {"1"}}
	if q.EventID != 0 {
		v.Set("id", strconv.FormatUint(q.EventID, 10))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	for k, s := range map[string]string{"ruleId": q.RuleID, "mode": q.Mode, "session": q.Session, "flow": q.Flow, "kind": q.Kind, "protocol": q.Protocol, "decision": q.Decision, "verdict": q.Verdict, "apdu": q.APDU, "category": q.Category, "cursor": q.Cursor} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.Detections {
		v.Set("detections", "1")
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.Format(time.RFC3339Nano))
	}
	return v
}

func (q Query) Matches(e Event) bool {
	if q.RuleID != "" && e.Attributes["ruleId"] != q.RuleID {
		return false
	}
	if q.Mode != "" && e.Attributes["mode"] != q.Mode {
		return false
	}
	if q.EventID != 0 && q.EventID != e.ID {
		return false
	}
	if q.Detections && e.Kind != "service.av.detected" && e.Kind != "service.av.block_flow" {
		return false
	}
	if q.Session != "" && sessionKey(e) != q.Session {
		return false
	}
	if q.Flow != "" && e.FlowID != q.Flow && sessionKey(e) != q.Flow {
		return false
	}
	if q.Protocol != "" && !strings.EqualFold(e.Proto, q.Protocol) {
		return false
	}
	if q.Decision != "" && !attributeEquals(e, "decision", q.Decision) {
		return false
	}
	if q.Verdict != "" && !attributeEquals(e, "outcome", q.Verdict) && !attributeEquals(e, "action", q.Verdict) {
		return false
	}
	if q.APDU != "" && !implicated(Event{Attributes: map[string]any{"apdu_id": q.APDU}}, e) {
		return false
	}
	if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
		return false
	}
	if q.Cursor != "" && !newer(q.before, e) {
		return false
	}
	if q.Kind != "" {
		matched := false
		for _, prefix := range strings.Split(q.Kind, ",") {
			if prefix = strings.TrimSpace(prefix); prefix != "" && strings.HasPrefix(e.Kind, prefix) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	switch q.Category {
	case "service":
		return strings.HasPrefix(e.Kind, "service.")
	case "proxy":
		return strings.HasPrefix(e.Kind, "service.envoy.") || strings.HasPrefix(e.Kind, "service.nginx.")
	case "dpi":
		return e.Proto != "firewall" && !strings.HasPrefix(e.Kind, "service.")
	case "firewall", "iec104":
		return e.Proto == q.Category
	}
	return true
}

func attributeEquals(e Event, key, value string) bool {
	s, _ := e.Attributes[key].(string)
	return strings.EqualFold(s, value)
}

func encodeCursor(e Event) string {
	return base64.RawURLEncoding.EncodeToString([]byte(e.Timestamp.UTC().Format(time.RFC3339Nano) + "|" + strconv.FormatUint(e.ID, 10)))
}
func decodeCursor(raw string) (Event, error) {
	var e Event
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return e, fmt.Errorf("invalid cursor")
	}
	parts := strings.Split(string(b), "|")
	if len(parts) != 2 {
		return e, fmt.Errorf("invalid cursor")
	}
	e.Timestamp, err = time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return e, fmt.Errorf("invalid cursor")
	}
	e.ID, err = strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return e, fmt.Errorf("invalid cursor")
	}
	return e, nil
}

// QueryPage filters/deduplicates before limit and uses chronological ordering,
// unlike the legacy priority page. more carries a source's pre-merge truncation.
func QueryPage(candidates []Event, q Query, truncated, more bool) Page {
	out := make([]Event, 0)
	seen := make(map[uint64]bool, len(candidates))
	for _, e := range candidates {
		if q.Matches(e) && !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return newer(out[i], out[j]) })
	if q.Limit > 0 && len(out) > q.Limit {
		more = true
		out = out[:q.Limit]
	}
	page := Page{Events: out, HistoryTruncated: truncated}
	if more && len(out) > 0 {
		page.NextCursor = encodeCursor(out[len(out)-1])
	}
	return page
}

func (s *Store) QueryTelemetry(q Query) Page {
	if s == nil {
		return Page{Events: []Event{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidates := append([]Event(nil), s.general.events...)
	candidates = append(candidates, s.denies.events...)
	for _, r := range s.incidents.groups {
		candidates = append(candidates, r.events...)
	}
	return QueryPage(candidates, q, s.historyTruncated, false)
}
