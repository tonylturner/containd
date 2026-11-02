// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"go.uber.org/zap"
)

func testProtectionCoordinator(t *testing.T, dp protectionPlane) *protectionCoordinator {
	t.Helper()
	c := newProtectionCoordinator(context.Background(), dp, zap.NewNop().Sugar())
	t.Cleanup(c.close)
	return c
}

func protectionRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	setProtectionHeaders(r, "test-apply", "", "test-running")
	return r
}

func setProtectionHeaders(r *http.Request, id, previous, revision string) {
	r.Header.Set(protection.ApplyIDHeader, id)
	r.Header.Set(protection.EngineBootIDHeader, engineBootID)
	r.Header.Set(protection.RunningRevisionHeader, revision)
	r.Header.Set(protection.ApplyModeHeader, string(protection.ModeNormal))
	r.Header.Set(protection.PreviousApplyIDHeader, previous)
}
