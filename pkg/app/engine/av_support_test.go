// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

type failingAVApplier struct{ applied int }

func (f *failingAVApplier) Apply(context.Context, config.AVConfig) error {
	f.applied++
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
	if runtime.GOOS != "linux" {
		// WireGuard cannot apply off Linux and is reported first.
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("non-linux services apply = %d %s", rec.Code, rec.Body)
		}
		return
	}
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "AV service apply failed: clamd not ready") {
		t.Fatalf("AV failure was hidden: %d %s", rec.Code, rec.Body)
	}
}

// startingAVApplier is a backend still starting: its apply ran out of time.
type startingAVApplier struct{}

func (startingAVApplier) Apply(context.Context, config.AVConfig) error {
	return fmt.Errorf("clamd not ready: %w", context.DeadlineExceeded)
}

func TestServicesApplyReportsStartingBackendAsPending(t *testing.T) {
	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	servicesHandler(zap.NewNop().Sugar(), dp, nil, nil, startingAVApplier{}, nil, testProtectionCoordinator(t, dp)).ServeHTTP(rec, protectionRequest(http.MethodPost, "/internal/services", strings.NewReader(`{}`)))
	if runtime.GOOS != "linux" {
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("non-linux services apply = %d %s", rec.Code, rec.Body)
		}
		return
	}
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

func TestAVApplyPending(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-expired.Done()
	live := context.Background()
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"no error", expired, nil, false},
		{"refused by backend", live, errors.New("unsupported av mode"), false},
		{"apply ran out of time", expired, errors.New("clamd not ready: dial unix: no such file"), true},
		{"deadline in the error", live, fmt.Errorf("clamd not ready: %w", context.DeadlineExceeded), true},
	}
	for _, tc := range cases {
		if got := avApplyPending(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: pending = %v, want %v", tc.name, got, tc.want)
		}
	}
}
