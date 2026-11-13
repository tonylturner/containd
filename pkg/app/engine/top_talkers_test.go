// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestTopTalkersClampAndShape(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := range 1002 {
		e.HandlePacket(capture.Packet{Timestamp: time.Now(), SrcIP: net.IPv4(10, byte(i/256), byte(i%256), 1), DstIP: net.IPv4(192, 0, 2, 1), Proto: 17, Transport: "udp", PortsValid: true, SrcPort: 50000, DstPort: 50001})
	}
	for _, tc := range []struct {
		query string
		want  int
	}{{"", 10}, {"bad", 10}, {"-1", 1}, {"0", 1}, {"1", 1}, {"1000", 1000}, {"1001", 1000}} {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/internal/stats/top-talkers?n="+tc.query, nil)
			w := httptest.NewRecorder()
			topTalkersHandler(e).ServeHTTP(w, r)
			var got stats.TopTalkers
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || len(got.Rows) != tc.want || got.Semantics != "recent" || got.Limit != limits.DefaultMaxTopTalkers || got.Evicted != 0 || got.Retained != 1002 || !got.Complete || got.Since.IsZero() {
				t.Fatalf("shape/clamp %+v status %d", got, w.Code)
			}
		})
	}
}
