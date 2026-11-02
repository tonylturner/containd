// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSimulationReplayWire(t *testing.T) {
	body := `{"running":true,"runId":"run-1","loops":3,"captureSet":"containd-demo/1","capture":"modbus/operations.pcap","error":""}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/internal/simulation" {
			t.Error(r.URL.Path)
		}
		if r.Method == http.MethodPost && string(data) != `{"action":"start"}` {
			t.Error(string(data))
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL)
	for _, call := range []func() (SimulationStatus, error){func() (SimulationStatus, error) { return c.SimulationStatus(context.Background()) }, func() (SimulationStatus, error) { return c.SimulationControl(context.Background(), "start") }} {
		st, err := call()
		if err != nil || !st.Running || st.RunID != "run-1" || st.Loops != 3 || st.CaptureSet != "containd-demo/1" || st.Capture != "modbus/operations.pcap" || st.Error != "" {
			t.Fatal(st, err)
		}
		data, err := json.Marshal(st)
		if err != nil || string(data) != body {
			t.Fatal(string(data), err)
		}
	}
}
