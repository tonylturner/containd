// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
	r.Header.Set(applyIDHeader, "test-apply")
	return r
}
