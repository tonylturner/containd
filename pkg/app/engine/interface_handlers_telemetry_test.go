// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

type interfaceObserver struct {
	calls  int
	ifaces []config.Interface
}

func (o *interfaceObserver) SetTelemetryInterfaces(_ context.Context, ifaces []config.Interface) error {
	o.calls++
	o.ifaces = ifaces
	return nil
}

func TestTelemetryInterfacesAppliedWithoutOwnership(t *testing.T) {
	t.Setenv("CONTAIND_ADDRESS_STATE_PATH", filepath.Join(t.TempDir(), "addresses.json"))
	observer := &interfaceObserver{}
	h := interfacesHandler(zap.NewNop().Sugar(), nil, observer)
	for _, tc := range []struct {
		body          string
		status, calls int
	}{{"[]", 200, 1}, {"{", 400, 1}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/interfaces", strings.NewReader(tc.body)))
		if rec.Code != tc.status || observer.calls != tc.calls {
			t.Fatalf("status %d calls %d: %s", rec.Code, observer.calls, rec.Body.String())
		}
	}
	if observer.ifaces == nil || len(observer.ifaces) != 0 {
		t.Fatal("applied empty set must not mean not-applied")
	}
}
