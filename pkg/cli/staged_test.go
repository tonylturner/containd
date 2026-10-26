// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMutationOutputDistinguishesStagedAndOperational(t *testing.T) {
	for _, state := range []string{"", "staged", "committed"} {
		t.Run("header="+state, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Containd-Config", state)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			api := &API{BaseURL: server.URL}
			// Deliberately cross header states with config, operational, and new paths.
			for _, path := range []string{"/api/v1/zones", "/api/v1/services/av/update", "/api/v1/new-endpoint"} {
				for _, method := range []string{"POST", "PATCH", "DELETE"} {
					var out bytes.Buffer
					var err error
					switch method {
					case "POST":
						err = api.postJSON(context.Background(), path, nil, &out)
					case "PATCH":
						err = api.patchJSON(context.Background(), path, nil, &out)
					case "DELETE":
						err = api.delete(context.Background(), path, &out)
					}
					want := "ok\n"
					if state == "staged" {
						want = stagedMessage + "\n"
					}
					if err != nil || out.String() != want {
						t.Fatalf("%s %s output=%q want=%q error=%v", method, path, out.String(), want, err)
					}
				}
			}
		})
	}
}

func TestFailedMutationDoesNotClaimStaged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Containd-Config", "staged")
		http.Error(w, "invalid candidate", http.StatusBadRequest)
	}))
	defer server.Close()
	var out bytes.Buffer
	api := &API{BaseURL: server.URL}
	if err := api.postJSON(context.Background(), "/api/v1/firewall/rules", nil, &out); err == nil || out.Len() != 0 {
		t.Fatalf("failed mutation output=%q error=%v", out.String(), err)
	}
}
