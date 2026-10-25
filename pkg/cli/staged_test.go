// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMutationOutputDistinguishesStagedAndOperational(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	api := &API{BaseURL: server.URL}
	for _, path := range []string{
		"/config", "/config/import", "/config/candidate", "/firewall/rules",
		"/firewall/ics-rules", "/firewall/nat", "/interfaces", "/interfaces/assign",
		"/zones", "/assets", "/objects", "/routing", "/dataplane", "/pcap/config",
		"/services/syslog", "/services/proxy/forward", "/services/proxy/reverse",
		"/templates/apply", "/learn/apply",
		"/config/commit", "/config/commit_confirmed", "/config/confirm", "/config/rollback",
		"/interfaces/reconcile", "/routing/reconcile", "/pcap/start", "/pcap/stop",
		"/dataplane/blocks/host", "/dataplane/blocks/flow", "/system/factory-reset", "/learn",
	} {
		t.Run(path, func(t *testing.T) {
			var out bytes.Buffer
			if err := api.postJSON(context.Background(), "/api/v1"+path, map[string]any{}, &out); err != nil {
				t.Fatal(err)
			}
			want := "ok\n"
			switch path {
			case "/config", "/config/import", "/config/candidate", "/firewall/rules",
				"/firewall/ics-rules", "/firewall/nat", "/interfaces", "/interfaces/assign",
				"/zones", "/assets", "/objects", "/routing", "/dataplane", "/pcap/config",
				"/services/syslog", "/services/proxy/forward", "/services/proxy/reverse",
				"/templates/apply", "/learn/apply":
				want = stagedMessage + "\n"
			}
			if out.String() != want {
				t.Fatalf("output=%q want=%q", out.String(), want)
			}
		})
	}
	for _, method := range []string{"PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			var out bytes.Buffer
			var err error
			if method == "PATCH" {
				err = api.patchJSON(context.Background(), "/api/v1/interfaces/wan", map[string]any{}, &out)
			} else {
				err = api.delete(context.Background(), "/api/v1/firewall/rules/example", &out)
			}
			if err != nil || !strings.Contains(out.String(), stagedMessage) {
				t.Fatalf("output=%q error=%v", out.String(), err)
			}
		})
	}
}

func TestFailedMutationDoesNotClaimStaged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid candidate", http.StatusBadRequest)
	}))
	defer server.Close()
	var out bytes.Buffer
	api := &API{BaseURL: server.URL}
	if err := api.postJSON(context.Background(), "/api/v1/firewall/rules", nil, &out); err == nil || out.Len() != 0 {
		t.Fatalf("failed mutation output=%q error=%v", out.String(), err)
	}
}
