// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConntrackUnavailableVersusEmpty(t *testing.T) {
	unavailable := newRuntimeMockEngine()
	unavailable.conntrackErr = errors.New("ctnetlink: operation not permitted")
	for _, tc := range []struct {
		name   string
		engine EngineClient
		status int
		body   string
	}{{"missing", &mockEngine{}, 503, "conntrack backend unavailable"}, {"denied", unavailable, 502, "operation not permitted"}, {"empty", newRuntimeMockEngine(), 200, "[]"}} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServerWithEngine(&mockStore{}, nil, tc.engine)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/conntrack", nil))
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.body) {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestConntrackKillContract(t *testing.T) {
	engine := newRuntimeMockEngine()
	s := NewServerWithEngine(&mockStore{}, nil, engine)
	for _, tc := range []struct {
		body   string
		status int
	}{{`{"proto":"tcp","src":"192.0.2.1","dst":"192.0.2.2","sport":1234,"dport":443,"scope":"client-service","durationSecs":30}`, 200}, {`{"proto":"tcp","src":"192.0.2.1","dst":"192.0.2.2","sport":1234,"dport":443,"durationSecs":3601}`, 400}, {`{"proto":"tcp","src":"192.0.2.1","dst":"192.0.2.2","dport":443}`, 400}} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/conntrack/kill", bytes.NewBufferString(tc.body)))
		if rec.Code != tc.status {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		if rec.Code == 200 && (!strings.Contains(rec.Body.String(), `"revocationInstalled":true`) || strings.Contains(rec.Body.String(), `"status":"deleted"`) || engine.conntrackDeleteReq.Scope != "client-service" || engine.conntrackDeleteReq.DurationSecs != 30) {
			t.Fatalf("old kill contract: %s, %+v", rec.Body.String(), engine.conntrackDeleteReq)
		}
	}
}

// ICMP and ICMPv6 kills select the identifier, type and code instead of
// ports, and the audit log names them.
func TestConntrackKillICMPContract(t *testing.T) {
	engine := newRuntimeMockEngine()
	audits := &mockAuditStore{}
	s := NewServerWithEngine(&mockStore{}, audits, engine)
	for _, tc := range []struct {
		body, target string
		status       int
	}{
		{`{"proto":"icmp","src":"192.0.2.1","dst":"192.0.2.2","icmpId":4660,"icmpType":8}`, "icmp [192.0.2.1] → [192.0.2.2] id 4660 type 8 code 0", 200},
		{`{"proto":"icmpv6","src":"2001:db8::1","dst":"2001:db8::2","icmpId":0,"icmpType":128,"scope":"client-service"}`, "icmpv6 [2001:db8::1] → [2001:db8::2] id 0 type 128 code 0", 200},
		{`{"proto":"icmp","src":"192.0.2.1","dst":"192.0.2.2","icmpId":4660}`, "", 400},
		{`{"proto":"icmp","src":"192.0.2.1","dst":"192.0.2.2","sport":1,"dport":2,"icmpType":8}`, "", 400},
		{`{"proto":"icmpv6","src":"192.0.2.1","dst":"192.0.2.2","icmpType":128}`, "", 400},
	} {
		before := len(audits.records)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, authedRequest(http.MethodPost, "/api/v1/conntrack/kill", bytes.NewBufferString(tc.body)))
		if rec.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.body, rec.Code, rec.Body.String())
		}
		if tc.status != 200 {
			continue
		}
		if len(audits.records) != before+1 || audits.records[before].Target != tc.target || engine.conntrackDeleteReq.ICMPType == 0 {
			t.Fatalf("%s: audit %+v request %+v", tc.body, audits.records[before:], engine.conntrackDeleteReq)
		}
	}
}
