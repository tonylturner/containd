// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"errors"
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
	servicesHandler(zap.NewNop().Sugar(), dp, nil, nil, av).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/services", strings.NewReader(`{}`)))
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
