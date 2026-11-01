// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"gopkg.in/yaml.v3"
)

type monitoringEngine struct {
	*runtimeMockEngine
	err       error
	mutations int
}

func (m *monitoringEngine) ListInterfaceState(context.Context) ([]config.InterfaceState, error) {
	return nil, m.err
}
func (m *monitoringEngine) AddSignature(context.Context, signatures.Signature) error {
	m.mutations++
	return m.err
}
func (m *monitoringEngine) RemoveSignature(context.Context, string) (bool, error) {
	m.mutations++
	return true, m.err
}
func (m *monitoringEngine) ListSignatureMatches(context.Context, int) ([]signatures.Match, error) {
	return nil, m.err
}

func (m *monitoringEngine) ClearAnomalies(context.Context) error { m.mutations++; return m.err }
func (m *monitoringEngine) ListSignatures(context.Context) ([]signatures.Signature, error) {
	return nil, m.err
}

var monitoringOperations = []struct {
	method, path, body, unavailable, empty string
	status                                 int
	mutation                               bool
}{
	{"GET", "/flows", "", "engine flows unavailable", "[]", 200, false},
	{"GET", "/stats/protocols", "", "engine protocol statistics unavailable", "[]", 200, false},
	{"GET", "/stats/top-talkers", "", "engine top talkers unavailable", "[]", 200, false},
	{"GET", "/anomalies", "", "engine anomalies unavailable", "[]", 200, false},
	{"DELETE", "/anomalies", "", "engine anomalies unavailable", `{"status":"ok"}`, 200, true},
	{"GET", "/signatures", "", "engine signatures unavailable", "[]", 200, false},
	{"POST", "/signatures", `{"id":"custom","name":"Custom","severity":"high","conditions":[{"field":"proto","op":"equals","value":"modbus"}]}`, "engine signatures unavailable", "", 200, true},
	{"DELETE", "/signatures/custom", "", "engine signatures unavailable", "", 204, true},
	{"GET", "/signatures/matches", "", "engine signature matches unavailable", "[]", 200, false},
	{"GET", "/interfaces/state", "", "engine interface state unavailable", "[]", 200, false},
	{"GET", "/simulation", "", "engine simulation unavailable", `{"running":false}`, 200, false},
	{"POST", "/simulation", `{"action":"stop"}`, "engine simulation unavailable", `{"running":false}`, 200, false},
}

func TestMonitoringAvailability(t *testing.T) {
	for _, op := range monitoringOperations {
		t.Run(op.method+op.path, func(t *testing.T) {
			modes := []string{"nil", "missing capability", "failed", "empty"}
			// Interface state is required by EngineClient, not optional.
			if op.path == "/interfaces/state" {
				modes = []string{"nil", "failed", "empty"}
			}
			for _, mode := range modes {
				t.Run(mode, func(t *testing.T) {
					m := &monitoringEngine{runtimeMockEngine: newRuntimeMockEngine()}
					var engine EngineClient = m
					switch mode {
					case "nil":
						engine = nil
					case "missing capability":
						engine = &mockEngine{}
					case "failed":
						m.err = errors.New("private upstream failure")
						m.flowsErr = m.err
						m.protoStatsErr = m.err
						m.topTalkersErr = m.err
						m.anomaliesErr = m.err
						m.simErr = m.err
					}
					server := NewServerWithEngine(&mockStore{}, nil, engine)
					req := authedRequest(op.method, "/api/v1"+op.path, strings.NewReader(op.body))
					req.Header.Set("Content-Type", "application/json")
					rec := httptest.NewRecorder()
					serveWithConfigRevision(t, server, rec, req)
					if mode != "empty" {
						if rec.Code != http.StatusServiceUnavailable {
							t.Fatalf("status %d: %s", rec.Code, rec.Body)
						}
						var got map[string]string
						if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 1 || got["error"] != op.unavailable {
							t.Fatalf("unavailable body: %s (%v)", rec.Body, err)
						}
						if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
							t.Fatal("expected JSON")
						}
					} else {
						if rec.Code != op.status {
							t.Fatalf("status %d: %s", rec.Code, rec.Body)
						}
						if op.empty != "" && strings.TrimSpace(rec.Body.String()) != op.empty {
							t.Fatalf("empty body: %s", rec.Body)
						}
					}
					if op.mutation && (mode == "empty" || mode == "failed") && m.mutations != 1 {
						t.Fatalf("backend calls: %d", m.mutations)
					}
				})
			}
		})
	}
}

func TestMonitoringOpenAPIUnavailableResponses(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema struct {
						Ref string `yaml:"$ref"`
					}
				}
			}
		}
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for _, op := range monitoringOperations {
		path := op.path
		if path == "/signatures/custom" {
			path = "/signatures/{id}"
		}
		ref := spec.Paths[path][strings.ToLower(op.method)].Responses["503"].Content["application/json"].Schema.Ref
		if ref != "#/components/schemas/ErrorResponse" {
			t.Errorf("%s %s 503 schema: %q", op.method, path, ref)
		}
	}
}
