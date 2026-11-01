// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestEvidenceAuditStatus(t *testing.T) {
	for _, state := range []string{"ok", "degraded", "recovered", "unknown"} {
		t.Run(state, func(t *testing.T) {
			failures := 0
			if state == "degraded" || state == "recovered" {
				failures = 3
			}
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET /api/v1/evidence/status": func(*http.Request) (*http.Response, error) {
					return jsonHTTPResponse(200, map[string]any{
						"audit":      map[string]any{"state": state, "failures": failures},
						"forwarding": []any{},
					}, nil), nil
				},
			}}
			api := &API{BaseURL: "http://localhost:8080", Client: client}
			var out bytes.Buffer
			if err := showAudit(api)(context.Background(), &out, []string{"--status"}); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"Audit persistence: " + state, "Failed writes since process start: " + strconv.Itoa(failures), "Operations continue", "No forwarding streams reported."} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %q: %s", want, &out)
				}
			}
			if err := showAudit(api)(context.Background(), io.Discard, []string{"--unsupported"}); err == nil {
				t.Fatal("accepted unsupported flag")
			}
		})
	}
}

func TestEvidenceForwardingOffsetsAndLoss(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/evidence/status": func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{
				"audit":{"state":"ok","failures":0},
				"forwarding":[{"destination":"tcp://collector:514","source":"engine","state":"recovered",
					"sentThrough":"9223372036854775809","backlog":13,"lost":7}]
			}`)), Header: http.Header{}}, nil
		},
	}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	var out bytes.Buffer
	if err := showAudit(api)(context.Background(), &out, []string{"--status"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"9223372036854775809", "recovered", "BACKLOG", "LOST", "13", "7"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
}

func TestEvidenceStatusUnavailable(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/evidence/status": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(503, map[string]string{"error": "unavailable"}, nil), nil
		},
	}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	var out bytes.Buffer
	if err := showAudit(api)(context.Background(), &out, []string{"--status"}); err == nil || out.Len() != 0 {
		t.Fatalf("unavailable status returned success: err=%v output=%s", err, &out)
	}
}

func TestEvidenceSyslogProgress(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/services/status": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, map[string]any{"syslog": map[string]any{
				"events": []any{
					map[string]any{"destination": "tcp://collector:514", "source": "engine", "backlog": 13, "sent": 21, "failed": 3, "lost": 7,
						"continuity_unknown": 2, "epoch": "run-1", "offset": "9223372036854775809", "last_error": "source offline"},
					map[string]any{"destination": "udp://other:514", "source": "services", "backlog": 0, "sent": 4, "failed": 0, "lost": 0,
						"continuity_unknown": 0, "epoch": "run-2", "offset": "4"},
				},
			}}, nil), nil
		},
	}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	var out bytes.Buffer
	if err := showSyslogStatus(api)(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"source=engine", "source=services", "backlog: 13", "sent: 21", "failed: 3", "lost: 7",
		"continuity_unknown: 2", "offset: 9223372036854775809", "source offline", "no backfill"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
}

func TestEvidenceHealthCLI(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/health": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, map[string]any{"status": "ok", "evidence": map[string]string{"state": "degraded"}}, nil), nil
		},
	}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	var out bytes.Buffer
	if err := showHealth(api)(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "evidence.state") || !strings.Contains(out.String(), "degraded") {
		t.Fatalf("evidence health hidden: %s", &out)
	}
}
