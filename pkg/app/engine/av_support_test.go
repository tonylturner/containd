// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

type failingAVApplier struct {
	testServiceOwner
	applied int
}

func (a *failingAVApplier) Apply(context.Context, config.AVConfig) error {
	a.applied++
	return errors.New("clamd not ready")
}

func TestServicesApplyReportsAVFailure(t *testing.T) {
	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	av := &failingAVApplier{}
	rec := httptest.NewRecorder()
	servicesHandler(zap.NewNop().Sugar(), dp, nil, nil, av, nil, testProtectionCoordinator(t, dp)).ServeHTTP(rec, protectionRequest(http.MethodPost, "/internal/services", strings.NewReader(`{}`)))
	if av.applied != 1 {
		t.Fatalf("AV applied %d times, want 1", av.applied)
	}
	var result engineapi.ServicesApplyResult
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatalf("services apply = %d %s", rec.Code, rec.Body)
	}
	for _, fault := range result.Faults {
		if fault.Service == config.ServiceAV && fault.Kind == "runtime" && fault.Message == "runtime apply failed" {
			return
		}
	}
	t.Fatalf("missing AV runtime fault: %+v", result)
}

// startingAVApplier is a backend still starting: its apply ran out of time.
type startingAVApplier struct{ testServiceOwner }

func (*startingAVApplier) Apply(context.Context, config.AVConfig) error {
	return fmt.Errorf("clamd not ready: %w", context.DeadlineExceeded)
}

func TestServicesApplyReportsStartingBackendAsPending(t *testing.T) {
	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	servicesHandler(zap.NewNop().Sugar(), dp, nil, nil, &startingAVApplier{}, nil, testProtectionCoordinator(t, dp)).ServeHTTP(rec, protectionRequest(http.MethodPost, "/internal/services", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "scanning is pending") {
		t.Fatalf("starting backend failed the apply: %d %s", rec.Code, rec.Body)
	}
	pending := 0
	for _, ev := range dp.Events().List(10) {
		if ev.Kind == gateEventPending {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("pending events %d, want 1", pending)
	}
}

func (a *failingAVApplier) ApplyDelivery(ctx context.Context, meta protection.Metadata, cfg config.AVConfig) (protection.OwnerOutcome, error) {
	return a.testServiceOwner.apply(ctx, meta, protection.SubsystemAV, cfg.Enabled, cfg, func(ctx context.Context) error { return a.Apply(ctx, cfg) })
}

func (a *startingAVApplier) ApplyDelivery(ctx context.Context, meta protection.Metadata, cfg config.AVConfig) (protection.OwnerOutcome, error) {
	return a.testServiceOwner.apply(ctx, meta, protection.SubsystemAV, cfg.Enabled, cfg, func(ctx context.Context) error { return a.Apply(ctx, cfg) })
}
