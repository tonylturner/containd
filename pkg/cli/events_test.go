// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestEventsFlags(t *testing.T) {
	for _, args := range [][]string{{"--session"}, {"--unknown", "s"}, {"--limit", "0"}, {"--since", "yesterday"}, {"--cursor", "bad"}, {"--session", "--flow"}} {
		if _, _, err := eventQueryPath(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	path, filtered, err := eventQueryPath([]string{"--session", "s/a", "--flow", "f", "--kind", "ics.", "--protocol", "iec104", "--decision", "deny", "--verdict", "drop_failed", "--since", "2026-01-01T00:00:00Z", "--limit", "1"})
	if err != nil || !filtered {
		t.Fatal(path, err)
	}
	u, _ := url.Parse(path)
	if u.Query().Get("session") != "s/a" {
		t.Fatal(path)
	}
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){"GET /api/v1/events": func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("session") != "s" {
			t.Error(r.URL)
		}
		return jsonHTTPResponse(200, dpevents.Page{Events: []dpevents.Event{{ID: 7, Kind: "ics.decision"}}, NextCursor: "next", HistoryTruncated: true, EngineError: "offline"}, nil), nil
	}}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	var out bytes.Buffer
	if err := showEvents(api)(context.Background(), &out, []string{"--session", "s"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ics.decision", "history may have gaps", "Next cursor: next", "offline"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
}
