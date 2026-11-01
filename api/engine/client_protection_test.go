// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestApplyProtectionHeaderAndObservation(t *testing.T) {
	for _, response := range []string{"valid", "empty", "malformed", "other apply"} {
		t.Run(response, func(t *testing.T) {
			ctx := NewApplyContext(context.Background())
			id := ApplyID(ctx)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				if r.Header.Get(ApplyIDHeader) != id || len(id) == 0 || len(id) > 64 {
					t.Errorf("apply header=%q want %q", r.Header.Get(ApplyIDHeader), id)
				}
				if r.URL.Path != "/internal/apply_rules" {
					_, _ = io.WriteString(w, `{"faults":[]}`)
					return
				}
				switch response {
				case "valid", "other apply":
					applyID := id
					if response == "other apply" {
						applyID = id + "-other"
					}
					_ = json.NewEncoder(w).Encode(dpengine.ProtectionStatus{BootID: "boot", ApplyID: applyID, State: "pending", ObservedAt: time.Now()})
				case "malformed":
					_, _ = io.WriteString(w, `bad json`)
				}
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL)
			if _, err := client.ConfigureServices(ctx, config.ServicesConfig{}); err != nil {
				t.Fatal(err)
			}
			if err := client.Configure(ctx, config.DataPlaneConfig{}); err != nil {
				t.Fatal(err)
			}
			st, err := client.ApplyRules(ctx, rules.Snapshot{})
			if err != nil || st.ApplyID != id {
				t.Fatalf("observation=%+v err=%v", st, err)
			}
			want := "unknown"
			if response == "valid" {
				want = "pending"
			}
			if st.State != want {
				t.Fatalf("state=%s want %s", st.State, want)
			}
			if ApplyID(NewApplyContext(ctx)) == id {
				t.Fatal("nested compensation reused ID")
			}
		})
	}
}

func TestApplyProtectionSupersededError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		w.WriteHeader(409)
		_, _ = io.WriteString(w, `{"error":"application was superseded","code":"apply_superseded"}`)
	}))
	defer server.Close()
	client := NewHTTPClient(server.URL)
	ctx := NewApplyContext(context.Background())
	_, servicesErr := client.ConfigureServices(ctx, config.ServicesConfig{})
	configErr := client.Configure(ctx, config.DataPlaneConfig{})
	_, rulesErr := client.ApplyRules(ctx, rules.Snapshot{})
	for _, err := range []error{servicesErr, configErr, rulesErr} {
		if err == nil || !strings.Contains(err.Error(), "apply_superseded") {
			t.Fatalf("lost rejection: %v", err)
		}
	}
}

func TestRetryProtectionWire(t *testing.T) {
	for _, code := range []string{"", "protection_superseded", "protection_not_retryable"} {
		t.Run(code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				if r.URL.Path != "/internal/protection/retry" || r.Header.Get(ApplyIDHeader) != "apply" || body["bootId"] != "boot" || len(body) != 1 {
					t.Errorf("retry request: %s %v %v", r.URL.Path, r.Header, body)
				}
				if code == "" {
					w.WriteHeader(202)
					return
				}
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
			}))
			defer server.Close()
			err := NewHTTPClient(server.URL).RetryProtection(context.Background(), "boot", "apply")
			if code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var conflict *ProtectionConflict
			if !errors.As(err, &conflict) || conflict.Code != code {
				t.Fatalf("conflict: %v", err)
			}
		})
	}
}

func TestRuntimeHealthProtectionBootIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"bootId": "new", "iec104Enforcement": map[string]bool{}, "protection": dpengine.ProtectionStatus{BootID: "old", ApplyID: "old-apply", State: "protecting", ObservedAt: time.Now()}})
	}))
	defer server.Close()
	health, err := NewHTTPClient(server.URL).RuntimeHealth(context.Background())
	if err != nil || health.Protection.State != "unknown" || health.Protection.ApplyID != "" {
		t.Fatalf("stale observation: %+v %v", health, err)
	}
}
