// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTelemetryClient(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		ok         bool
	}{
		{"snapshot", `{"bootId":"boot","samples":[{"metric":"iface.rx_bytes","value":"18446744073709551615","epoch":"link"}],"unavailable":[{"source":"conduit","reason":"enforcement disabled"}]}`, 200, true},
		{"failure", "failed", 503, false}, {"invalid", "{", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/internal/telemetry/counters" {
					t.Error(r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			c := NewHTTPClient(server.URL)
			s, err := c.TelemetryCounters(context.Background())
			if (err == nil) != tc.ok {
				t.Fatal(err)
			}
			if tc.ok && (s.BootID != "boot" || s.Samples[0].Value != ^uint64(0) || len(s.Unavailable) != 1) {
				t.Fatal(s)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := c.TelemetryCounters(ctx); err == nil {
				t.Fatal("cancel ignored")
			}
		})
	}
}
