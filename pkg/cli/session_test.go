// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type sessionHTTP func(*http.Request) (*http.Response, error)

func (f sessionHTTP) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestSessionStatus(t *testing.T) {
	for _, tt := range []struct{ body, marker, status string }{
		{`{"changed":false}`, "(config)#", "Candidate matches running"},
		{`{"changed":true}`, "(config*)#", "Pending changes"},
		{`{"changed":true,"pendingConfirm":{"deadline":"2030-01-01T00:00:00Z"}}`, "(config*)#", "Confirmation pending until"},
		{`{"changed":false,"pendingConfirm":{"deadline":"2030-01-01T00:00:00Z"}}`, "(config)#", "Confirmation pending until"},
		{`{}`, "(config?)#", "Candidate status unavailable"},
		{`null`, "(config?)#", "Candidate status unavailable"},
	} {
		t.Run(tt.body, func(t *testing.T) {
			api := &API{BaseURL: "http://management", Client: sessionHTTP(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/config/diff" || r.Header.Get("X-Containd-If-Revision") != "" {
					t.Fatalf("status affected mutation authority: %v", r)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})}
			s := api.SessionStatus(context.Background())
			if !strings.Contains(s.Prompt("admin"), tt.marker) || !strings.Contains(s.String(), tt.status) {
				t.Fatalf("%+v: %s", s, s)
			}
			if s.Prompt("view") != "containd(view)> " {
				t.Fatal(s.Prompt("view"))
			}
		})
	}
	s := SessionStatus{Known: true, Changed: true, Refreshed: time.Now()}
	if !strings.Contains(s.String(), "Refreshed") {
		t.Fatal(s.String())
	}
}

func TestSessionFailureAndIdentity(t *testing.T) {
	api := &API{BaseURL: "http://management", Client: sessionHTTP(func(r *http.Request) (*http.Response, error) {
		body := `{"system":{"hostname":"lab-fw"}}`
		code := 200
		switch r.URL.Path {
		case "/api/v1/auth/me":
			body = `{"username":"operator","role":"view"}`
		case "/api/v1/config/diff":
			code = 503
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	entry, role := api.SessionEntry(context.Background())
	if role != "view" || !strings.Contains(entry, "Read-only CLI — lab-fw · operator/view") {
		t.Fatal(entry, role)
	}
	status := api.SessionStatus(context.Background())
	if status.Known || !strings.Contains(status.String(), "503") {
		t.Fatal(status)
	}
	err := SessionCommandError("pwd", io.EOF)
	if err != io.EOF {
		t.Fatal(err)
	}
}
