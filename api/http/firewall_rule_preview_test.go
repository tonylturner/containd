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
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type previewMockEngine struct {
	EngineClient
	entry  rules.Entry
	calls  int
	result dpengine.PreviewRuleResponse
	err    error
}

func (e *previewMockEngine) PreviewRule(_ context.Context, entry rules.Entry) (dpengine.PreviewRuleResponse, error) {
	e.calls++
	e.entry = entry
	return e.result, e.err
}

func TestPreviewFirewallRuleDelegates(t *testing.T) {
	result := dpengine.PreviewRuleResponse{MatchCount: 123, TotalEvents: 456,
		SampleMatches: []events.Event{{ID: 99, SrcIP: "10.30.30.30"}},
		TimeRange:     &dpengine.PreviewTimeRange{Start: time.Unix(1, 0).UTC(), End: time.Unix(20, 0).UTC()},
		Warnings: []enforce.RuleWarning{{RuleID: "candidate", Predicate: enforce.PredicateIdentity, Action: rules.ActionAllow,
			Message: "identity predicates are not enforced yet; ALLOW rule inactive"}}}
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
	NewServerWithEngine(&mockStore{}, nil, eng).ServeHTTP(rec, req)
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
		NewServerWithEngine(&mockStore{}, nil, eng).ServeHTTP(rec, req)
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
			NewServerWithEngine(&mockStore{}, nil, tc.engine).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
