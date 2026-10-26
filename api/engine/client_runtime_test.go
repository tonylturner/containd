// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

func TestListConntrackBackendErrorDetail(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"permission", "ctnetlink: operation not permitted\n", "engine conntrack status 503: ctnetlink: operation not permitted"},
		{"interrupted", "conntrack dump interrupted", "engine conntrack status 503: conntrack dump interrupted"},
		{"empty", "", "engine conntrack status 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/conntrack" || r.URL.Query().Get("limit") != "5" {
					t.Errorf("unexpected request %s", r.URL)
				}
				http.Error(w, tc.body, http.StatusServiceUnavailable)
			}))
			defer srv.Close()
			entries, err := NewHTTPClient(srv.URL).ListConntrack(context.Background(), 5)
			if err == nil || strings.TrimSpace(err.Error()) != tc.want || entries != nil {
				t.Fatalf("ListConntrack = %+v, %v; want nil, %q", entries, err, tc.want)
			}
		})
	}
}

func TestKillConntrackStepReporting(t *testing.T) {
	for _, body := range []string{`{"scope":"connection","matched":1,"deleted":0,"conntrackDeleted":false,"deleteError":"not found","revocationInstalled":true,"blockedUntil":"2026-10-26T12:00:00Z","closure":"TCP reset signalled on next packet"}`, `{"scope":"client-service","matched":2,"deleted":0,"conntrackDeleted":false,"revocationInstalled":false,"revocationError":"nft denied","closure":"not signalled"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req conntrack.KillRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.Scope != "client-service" || req.DurationSecs != 30 {
				t.Errorf("request %+v", req)
			}
			_, _ = io.WriteString(w, body)
		}))
		result, err := NewHTTPClient(srv.URL).DeleteConntrack(context.Background(), conntrack.KillRequest{Scope: "client-service", DurationSecs: 30})
		srv.Close()
		if err != nil || result.ConntrackDeleted || (result.DeleteError == "" && result.RevocationError == "") {
			t.Fatalf("result %+v %v", result, err)
		}
	}
}

func TestKillConntrackBackendErrorDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "conntrack dump interrupted", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, err := NewHTTPClient(srv.URL).DeleteConntrack(context.Background(), conntrack.KillRequest{})
	if err == nil || !strings.Contains(err.Error(), "conntrack dump interrupted") {
		t.Fatalf("error %v", err)
	}
}

func TestListConntrackSnapshot(t *testing.T) {
	for _, body := range []string{`{"entries":[]}`, `{}`, `{"entries":null}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		entries, err := NewHTTPClient(srv.URL).ListConntrack(context.Background(), 10)
		srv.Close()
		if body == `{"entries":[]}` {
			if err != nil || entries == nil || len(entries) != 0 {
				t.Fatalf("verified empty: %+v %v", entries, err)
			}
		} else if err == nil {
			t.Fatalf("missing snapshot accepted: %s", body)
		}
	}
}

func TestKillConntrackRejectsOldOrMalformedResponse(t *testing.T) {
	for _, body := range []string{`{"status":"deleted"}`, `{}`, `{"scope":"connection","matched":1,"deleted":1,"revocationInstalled":true,"closure":"pending"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, body)
		}))
		_, err := NewHTTPClient(srv.URL).DeleteConntrack(context.Background(), conntrack.KillRequest{})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "step details") {
			t.Fatalf("accepted %s: %v", body, err)
		}
	}
}
