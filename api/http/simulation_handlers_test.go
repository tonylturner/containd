// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/demo"
)

// HTTP tests fake the management controller, not the private engine endpoint.
type fakeDemoController struct {
	status demo.Status
	err    error
	action string
}

func (f *fakeDemoController) SimulationStatus(context.Context) (demo.Status, error) {
	return f.status, f.err
}
func (f *fakeDemoController) SimulationControl(_ context.Context, action string) (demo.Status, error) {
	f.action = action
	return f.status, f.err
}

func TestSimulationManagementShapeAndAudit(t *testing.T) {
	for _, action := range []string{"start", "stop"} {
		t.Run(action, func(t *testing.T) {
			p := demo.On
			if action == "stop" {
				p = demo.Off
			}
			controller := &fakeDemoController{status: demo.Status{Preference: p, Running: action == "start", Loops: 3, CaptureSet: "containd-demo/1", Capture: "modbus/operations.pcap", Error: "engine unreachable: offline", Reason: "engine unreachable"}}
			log := &mockAuditStore{}
			router := NewServerWithEngineAndServices(&mockStore{}, log, nil, nil, nil, controller)
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				rec := httptest.NewRecorder()
				req := authedRequest(method, "/api/v1/simulation", strings.NewReader(`{"action":"`+action+`"}`))
				req.Header.Set("Content-Type", "application/json")
				serveWithConfigRevision(t, router, rec, req)
				if rec.Code != 200 {
					t.Fatal(rec.Code, rec.Body)
				}
				var got map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if len(got) != 7 || got["preference"] != string(p) || got["loops"] != float64(3) || got["error"] != "engine unreachable: offline" || got["captureSet"] != "containd-demo/1" || got["capture"] != "modbus/operations.pcap" || got["reason"] != "engine unreachable" || got["running"] != (action == "start") {
					t.Fatal(got)
				}
			}
			if controller.action != action {
				t.Fatal(controller.action)
			}
			if len(log.records) != 1 || log.records[0].Action != "simulation."+action || log.records[0].Target != "demo" {
				t.Fatal(log.records)
			}
		})
	}
}

func TestSimulationValidationAndPersistenceFailure(t *testing.T) {
	controller := &fakeDemoController{err: errors.New("disk full")}
	router := NewServerWithEngineAndServices(&mockStore{}, nil, nil, nil, nil, controller)
	for _, tc := range []struct {
		body string
		code int
	}{{`{"action":"toggle"}`, 400}, {`{`, 400}, {`{"action":"stop"}`, 500}} {
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodPost, "/api/v1/simulation", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		serveWithConfigRevision(t, router, rec, req)
		if rec.Code != tc.code {
			t.Fatal(rec.Code, rec.Body)
		}
	}
}
