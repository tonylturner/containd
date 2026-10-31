// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type previewMockEngine struct {
	EngineClient
	forwards map[string]rules.ForwardMatch
	entry    rules.Entry
	calls    int
	result   dpengine.PreviewRuleResponse
	err      error
}

func (e *previewMockEngine) PreviewRule(_ context.Context, req dpengine.PreviewRuleRequest) (dpengine.PreviewRuleResponse, error) {
	e.calls++
	e.entry = req.Entry
	e.forwards = req.ForwardMatches
	return e.result, e.err
}

func TestPreviewFirewallRuleDelegates(t *testing.T) {
	result := dpengine.PreviewRuleResponse{MatchCount: 123, TotalEvents: 456,
		SampleMatches: []events.Event{{ID: 99, SrcIP: "10.30.30.30"}},
		TimeRange:     &dpengine.PreviewTimeRange{Start: time.Unix(1, 0).UTC(), End: time.Unix(20, 0).UTC()},
		Warnings: []enforce.RuleWarning{{RuleID: "candidate", Predicate: enforce.PredicateIdentity, Action: rules.ActionAllow,
			Message: "no bound address can match identities operator; the rule matches nothing until one is bound"}}}
	eng := &previewMockEngine{result: result}
	body := `{"id":"candidate","sourceZones":["control"],"destZones":["plant"],
		"sources":["10.60.60.10/32"],"destinations":["10.30.30.30/32"],"action":"ALLOW",
		"protocols":[{"name":"tcp","port":"2404"}],"identities":["operator"],
		"schedule":{"daysOfWeek":["Monday"],"startTime":"09:00","endTime":"17:00","timezone":"UTC"},
		"ics":{"protocol":"iec104","readOnly":true,"mode":"enforce","direction":"response",
		"typeIds":[1,30],"classes":["monitor"],"ca":[1],"ioa":[{"start":1,"end":100}]}}`
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/firewall/rules/preview", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	NewServerWithEngine(&mockStore{cfg: config.DefaultConfig()}, nil, eng).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d %s", rec.Code, rec.Body.String())
	}
	var got dpengine.PreviewRuleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, result) {
		t.Fatalf("response modified: %+v != %+v", got, result)
	}
	want := rules.Entry{ID: "candidate", SourceZones: []string{"control"}, DestZones: []string{"plant"},
		Sources: []string{"10.60.60.10/32"}, Destinations: []string{"10.30.30.30/32"},
		Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}}, Identities: []string{"operator"},
		Schedule: rules.SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "09:00", EndTime: "17:00", Timezone: "UTC"},
		ICS: rules.ICSPredicate{Protocol: "iec104", ReadOnly: true, Mode: "enforce", Direction: "response",
			TypeIDs: []int{1, 30}, Classes: []string{"monitor"}, CA: []uint16{1}, IOA: []rules.IOARange{{Start: 1, End: 100}}}}
	if eng.calls != 1 || !reflect.DeepEqual(eng.entry, want) {
		t.Fatalf("engine calls=%d entry=%+v, want %+v", eng.calls, eng.entry, want)
	}
}

// The previewed entry carries the action parameters of RATE_LIMIT and
// TAG rules.
func TestPreviewFirewallRuleCarriesActionParameters(t *testing.T) {
	for body, want := range map[string]rules.Entry{
		`{"id":"police","action":"RATE_LIMIT","rateLimit":{"packetsPerSecond":50,"burst":5}}`: {ID: "police", Action: rules.ActionRateLimit,
			RateLimit: &rules.RateLimit{PacketsPerSecond: 50, Burst: 5}},
		`{"id":"label","action":"TAG","tag":"plc"}`: {ID: "label", Action: rules.ActionTag, Tag: "plc"},
	} {
		eng := &previewMockEngine{}
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodPost, "/api/v1/firewall/rules/preview", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		NewServerWithEngine(&mockStore{cfg: config.DefaultConfig()}, nil, eng).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || eng.calls != 1 || !reflect.DeepEqual(eng.entry, want) {
			t.Fatalf("%s: status=%d entry=%+v, want %+v", body, rec.Code, eng.entry, want)
		}
	}
}

func TestPreviewFirewallRuleErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		engine     EngineClient
		want       int
	}{
		{"invalid JSON", `{`, &previewMockEngine{}, http.StatusBadRequest},
		{"engine failure", `{}`, &previewMockEngine{err: errors.New("offline")}, http.StatusBadGateway},
		{"no engine", `{}`, nil, http.StatusServiceUnavailable},
		{"no preview support", `{}`, newRuntimeMockEngine(), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := authedRequest(http.MethodPost, "/api/v1/firewall/rules/preview", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			NewServerWithEngine(&mockStore{cfg: config.DefaultConfig()}, nil, tc.engine).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestPreviewFirewallCandidateForwards(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "wan", Zone: "wan", Device: "wan0"}}
	cfg.Firewall.NAT.PortForwards = []config.PortForward{{ID: "candidate", Enabled: true, IngressZone: "wan", Proto: "tcp", ListenPort: 1502, DestIP: "10.0.0.2", DestPort: 502}, {ID: "disabled", IngressZone: "wan", Proto: "tcp", ListenPort: 1503, DestIP: "10.0.0.3"}}
	eng := &previewMockEngine{}
	rec := httptest.NewRecorder()
	req := authedRequest("POST", "/api/v1/firewall/rules/preview", strings.NewReader(`{"id":"via","action":"ALLOW","viaForwards":["candidate"]}`))
	req.Header.Set("Content-Type", "application/json")
	NewServerWithEngine(&mockStore{cfg: cfg}, nil, eng).ServeHTTP(rec, req)
	if rec.Code != 200 || !reflect.DeepEqual(eng.entry.ViaForwards, []string{"candidate"}) || len(eng.forwards) != 1 || eng.forwards["candidate"].Backend.String() != "10.0.0.2:502" || !reflect.DeepEqual(eng.forwards["candidate"].IngressDevices, []string{"wan0"}) {
		t.Fatalf("response=%d %s entry=%+v forwards=%+v", rec.Code, rec.Body, eng.entry, eng.forwards)
	}
}
