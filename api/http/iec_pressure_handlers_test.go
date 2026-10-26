// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/dp/engine"
)

type pressureClient struct{ err error }

func (p pressureClient) IEC104Diagnostics(context.Context) (engine.IEC104Pressure, error) {
	return engine.IEC104Pressure{HeldPackets: 7}, p.err
}

func TestIEC104DiagnosticsHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client any
		status int
	}{
		{"live", pressureClient{}, 200}, {"offline", pressureClient{errors.New("offline")}, 503}, {"unsupported", struct{}{}, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/v1/diagnostics/iec104", nil)
			iec104DiagnosticsHandler(tc.client)(c)
			if w.Code != tc.status {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if tc.status == 503 && w.Body.String() != `{"error":"engine IEC104 diagnostics unavailable"}` {
				t.Fatal(w.Body.String())
			}
		})
	}
}
