// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func testAdmission() protection.Admission {
	return protection.Admission{Metadata: protection.Metadata{BootID: "boot", ApplyID: "apply", RunningRevision: "running", Mode: protection.ModeNormal}}
}

func TestDeliveryAdmissionEveryMutation(t *testing.T) {
	for _, predecessor := range []protection.ApplyID{"", "previous"} {
		t.Run(string(predecessor), func(t *testing.T) {
			a := testAdmission()
			a.PreviousApplyID = predecessor
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				calls++
				for header, want := range map[string]string{protection.ApplyIDHeader: string(a.ApplyID), protection.EngineBootIDHeader: string(a.BootID), protection.RunningRevisionHeader: string(a.RunningRevision), protection.ApplyModeHeader: string(a.Mode), protection.PreviousApplyIDHeader: string(predecessor)} {
					if _, present := r.Header[http.CanonicalHeaderKey(header)]; !present || r.Header.Get(header) != want {
						t.Errorf("%s: %s=%q want %q", r.URL, header, r.Header.Get(header), want)
					}
				}
				// Missing telemetry must never undo known synchronous success.
				w.WriteHeader(http.StatusAccepted)
			}))
			defer server.Close()
			c := NewHTTPClient(server.URL)
			ctx := context.Background()
			for _, call := range []func() error{
				func() error { return c.Configure(ctx, a, config.DataPlaneConfig{}) },
				func() error { return c.ConfigureServices(ctx, a, config.ServicesConfig{}) },
				func() error { return c.ConfigureTrust(ctx, a, trust.Bundle{Revision: trust.NoRevision}) },
				func() error { return c.ApplyRules(ctx, a, rules.Snapshot{}) },
				func() error { return c.Retry(ctx, a) },
				func() error { return c.ConfigureInterfaces(ctx, a, nil, false) },
				func() error { return c.ConfigureInterfaces(ctx, a, nil, true) },
				func() error { return c.ConfigureRouting(ctx, a, config.RoutingConfig{}, false) },
				func() error { return c.ConfigureRouting(ctx, a, config.RoutingConfig{}, true) },
			} {
				if err := call(); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 9 {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestDeliveryConflicts(t *testing.T) {
	for _, code := range []string{"apply_input_changed", "apply_predecessor_changed", "engine_boot_changed", "apply_superseded", "protection_superseded"} {
		t.Run(code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
			}))
			defer server.Close()
			if err := NewHTTPClient(server.URL).Configure(context.Background(), testAdmission(), config.DataPlaneConfig{}); !errors.Is(err, convergence.ErrInputChanged) {
				t.Fatalf("conflict=%v", err)
			}
		})
	}
}

func TestObserveNeverInventsProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(map[string]any{"bootId": "boot", "iec104Enforcement": map[string]bool{}, "protection": dpengine.ProtectionStatus{BootID: "boot", ApplyID: "apply", State: "pending", ObservedAt: time.Now()}})
			return
		}
		_ = json.NewEncoder(w).Encode(dpengine.RulesetStatus{})
	}))
	defer server.Close()
	o, err := NewHTTPClient(server.URL).Observe(context.Background())
	if err != nil || o.BootID != "boot" || o.Engine.Installed != nil || len(o.Outcomes) != 0 {
		t.Fatalf("observation=%+v err=%v", o, err)
	}
}

func TestMissingRulesTelemetryKeepsBootAdmissibleWithoutReadiness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		a := testAdmission()
		_ = json.NewEncoder(w).Encode(map[string]any{"bootId": "boot", "iec104Enforcement": map[string]bool{},
			"protection": dpengine.ProtectionStatus{BootID: "boot", ApplyID: "apply", RunningRevision: a.RunningRevision,
				Mode: a.Mode, State: "protecting", ObservedAt: time.Now(),
				Installed: &protection.Acknowledgement{Metadata: a.Metadata, Operation: protection.OperationApply}}})
	}))
	defer server.Close()
	o, err := NewHTTPClient(server.URL).Observe(context.Background())
	if err != nil || o.BootID != "boot" || o.Engine.State != protection.StateUnknown || o.Engine.Installed == nil {
		t.Fatalf("missing rules telemetry: %+v %v", o, err)
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
