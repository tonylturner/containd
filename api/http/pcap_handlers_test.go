// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

type pcapStartErrorEngine struct {
	*runtimeMockEngine
	err error
}

func (e *pcapStartErrorEngine) StartPcap(context.Context, config.PCAPConfig) (pcap.Status, error) {
	return pcap.Status{}, e.err
}

func TestPCAPStartForwardsOverrideBodyToEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PCAP = config.PCAPConfig{
		Interfaces: []string{"stored"},
		Mode:       "once",
		Snaplen:    256,
		FilePrefix: "stored",
	}
	store := &mockStore{cfg: cfg, load: func() (*config.Config, error) {
		t.Error("explicit capture request must not read persisted defaults")
		return nil, errors.New("unexpected config read")
	}}
	engine := newRuntimeMockEngine()
	server := NewServerWithEngine(store, nil, engine)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/pcap/start", strings.NewReader(
		`{"interfaces":["override"],"zones":["lab"],"filter":{"port":"2404"}}`,
	))
	serveWithConfigRevision(t, server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("pcap start status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := engine.pcapStartCfg; len(got.Interfaces) != 1 || got.Interfaces[0] != "override" {
		t.Fatalf("engine start interfaces = %#v, want override body value", got.Interfaces)
	}
	if got := engine.pcapStartCfg.Zones; len(got) != 1 || got[0] != "lab" {
		t.Fatalf("engine start zones = %#v, want override body value", got)
	}
	if engine.pcapStartCfg.Filter.Port != "2404" {
		t.Fatalf("engine start port = %q, want 2404", engine.pcapStartCfg.Filter.Port)
	}
	if engine.pcapStartCfg.Mode != "" || engine.pcapStartCfg.Snaplen != 0 || engine.pcapStartCfg.FilePrefix != "" {
		t.Fatalf("engine start inherited omitted fields from stored config: %#v", engine.pcapStartCfg)
	}
	if store.calls != 0 || store.cfg.PCAP.Enabled {
		t.Fatalf("successful start saved config %d times: %#v", store.calls, store.cfg.PCAP)
	}
}

func TestPCAPStartWithoutBodyUsesStoredConfig(t *testing.T) {
	tests := []struct {
		name string
		body io.Reader
	}{
		{name: "nil body"},
		{name: "empty body", body: strings.NewReader(" \n\t")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.PCAP = config.PCAPConfig{
				Interfaces: []string{"stored"},
				Mode:       "once",
				Snaplen:    256,
			}
			store := &mockStore{cfg: cfg}
			engine := newRuntimeMockEngine()
			server := NewServerWithEngine(store, nil, engine)

			rec := httptest.NewRecorder()
			serveWithConfigRevision(t, server, rec, authedRequest(http.MethodPost, "/api/v1/pcap/start", test.body))

			if rec.Code != http.StatusOK {
				t.Fatalf("pcap start status = %d body=%s", rec.Code, rec.Body.String())
			}
			if got := engine.pcapStartCfg; len(got.Interfaces) != 1 || got.Interfaces[0] != "stored" ||
				got.Mode != "once" || got.Snaplen != 256 || !got.Enabled {
				t.Fatalf("engine start config = %#v, want stored settings enabled", got)
			}
			if store.calls != 0 || store.cfg.PCAP.Enabled {
				t.Fatalf("successful start changed persisted config: calls=%d cfg=%#v", store.calls, store.cfg.PCAP)
			}
		})
	}
}

func TestPCAPStartBodyWithoutSelectionRejectsStoredFallback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PCAP.Interfaces = []string{"stored"}
	store := &mockStore{cfg: cfg}
	engine := newRuntimeMockEngine()
	server := NewServerWithEngine(store, nil, engine)

	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, server, rec, authedRequest(
		http.MethodPost,
		"/api/v1/pcap/start",
		strings.NewReader(`{"snaplen":512}`),
	))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pcap start status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at least one interface or zone") {
		t.Fatalf("pcap start did not reject empty selection: %s", rec.Body.String())
	}
	if store.calls != 0 {
		t.Fatalf("invalid start saved config %d times, want 0", store.calls)
	}
	if len(engine.pcapStartCfg.Interfaces) != 0 {
		t.Fatalf("invalid start reached engine with interfaces %#v", engine.pcapStartCfg.Interfaces)
	}
}

func TestPCAPStartMapsEngineResolutionErrorToBadRequest(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PCAP = config.PCAPConfig{Interfaces: []string{"stored"}, Mode: "once", Snaplen: 256}
	original := cfg.PCAP
	store := &mockStore{cfg: cfg}
	engine := &pcapStartErrorEngine{
		runtimeMockEngine: newRuntimeMockEngine(),
		err:               errors.New(`pcap zone "ghost" has no configured interfaces`),
	}
	server := NewServerWithEngine(store, nil, engine)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/pcap/start", strings.NewReader(
		`{"zones":["ghost"]}`,
	))
	serveWithConfigRevision(t, server, rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pcap start status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ghost") {
		t.Fatalf("pcap start response did not name unknown zone: %s", rec.Body.String())
	}
	if store.calls != 0 || !reflect.DeepEqual(store.cfg.PCAP, original) {
		t.Fatalf("failed start changed stored config: calls=%d cfg=%#v, want %#v", store.calls, store.cfg.PCAP, original)
	}
}

func TestPCAPStartWithoutEngineDoesNotPersist(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	server := NewServerWithEngine(store, nil, nil)
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, server, rec, authedRequest(http.MethodPost, "/api/v1/pcap/start", strings.NewReader(
		`{"zones":["lan"],"filter":{"port":"502"}}`,
	)))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pcap start queued") {
		t.Fatalf("queued start status = %d body=%s", rec.Code, rec.Body.String())
	}
	if store.calls != 0 || store.cfg.PCAP.Enabled {
		t.Fatal("queued start persisted settings")
	}

}

func TestPCAPConfigDoesNotCallEngine(t *testing.T) {
	engineServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("staging called the engine")
		http.Error(w, "unexpected engine call", http.StatusBadRequest)
	}))
	defer engineServer.Close()

	store := &mockStore{cfg: config.DefaultConfig()}
	server := NewServerWithEngine(store, nil, engineclient.NewHTTPClient(engineServer.URL))
	rec := httptest.NewRecorder()
	req := authedRequest(
		http.MethodPost,
		"/api/v1/pcap/config",
		strings.NewReader(`{"enabled":true,"interfaces":["missing"]}`),
	)
	serveWithConfigRevision(t, server, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(store.cfg.PCAP.Interfaces) != 1 || store.cfg.PCAP.Interfaces[0] != "missing" {
		t.Fatal("settings not staged")
	}
}
