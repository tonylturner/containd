// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestCLICommandsHandlerIncludesExpectedCommands(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/cli/commands", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var commands []string
	if err := json.Unmarshal(rec.Body.Bytes(), &commands); err != nil {
		t.Fatalf("decode commands: %v", err)
	}
	if len(commands) == 0 {
		t.Fatal("expected commands")
	}
	if !containsString(commands, "show version") {
		t.Fatalf("expected show version command, got %v", commands)
	}
	if !containsString(commands, "show health") {
		t.Fatalf("expected show health command, got %v", commands)
	}
	if !containsString(commands, "commit confirmed") {
		t.Fatalf("expected admin command commit confirmed, got %v", commands)
	}
}

func TestCLIExecuteHandlerSupportsBlankAndCommandExecution(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/cli/execute", bytes.NewBufferString(`{"line":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for blank input, got %d body=%s", rec.Code, rec.Body.String())
	}
	var blankResp struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &blankResp); err != nil {
		t.Fatalf("decode blank response: %v", err)
	}
	if blankResp.Output != "" || blankResp.Error != "" {
		t.Fatalf("expected blank no-op response, got %+v", blankResp)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/cli/execute", bytes.NewBufferString(`{"line":"show version"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for show version, got %d body=%s", rec.Code, rec.Body.String())
	}
	var execResp struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}
	if !strings.Contains(execResp.Output, "containd") {
		t.Fatalf("expected version output, got %+v", execResp)
	}
	if execResp.Error != "" {
		t.Fatalf("unexpected execute error: %+v", execResp)
	}
}

func TestCLICompleteHandlerSuggestsConfigAwareArgs(t *testing.T) {
	store := &mockStore{cfg: &config.Config{
		Interfaces: []config.Interface{
			{Name: "wan"},
			{Name: "dmz"},
		},
		Zones: []config.Zone{
			{Name: "wan"},
			{Name: "dmz"},
		},
	}}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/cli/complete?line="+url.QueryEscape("set interface "), nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var suggestions []string
	if err := json.Unmarshal(rec.Body.Bytes(), &suggestions); err != nil {
		t.Fatalf("decode suggestions: %v", err)
	}
	if !containsString(suggestions, "wan") || !containsString(suggestions, "dmz") {
		t.Fatalf("expected interface suggestions, got %v", suggestions)
	}
}

func TestCLIWebsocketHandlerExecutesCommands(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	srv := httptest.NewServer(NewServer(store, nil))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/cli/ws"
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+testAdminToken)
	headers.Set("Origin", srv.URL)

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil {
			t.Fatalf("websocket dial failed: %v (status=%d)", err, resp.StatusCode)
		}
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close()

	var greeting struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := conn.ReadJSON(&greeting); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !strings.Contains(greeting.Output, "containd in-app CLI") {
		t.Fatalf("unexpected greeting: %+v", greeting)
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"line":"show version"}`)); err != nil {
		t.Fatalf("write command: %v", err)
	}

	var cmdResp struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if err := conn.ReadJSON(&cmdResp); err != nil {
		t.Fatalf("read command response: %v", err)
	}
	if !strings.Contains(cmdResp.Output, "containd") {
		t.Fatalf("unexpected websocket output: %+v", cmdResp)
	}
	if cmdResp.Error != "" {
		t.Fatalf("unexpected websocket error: %+v", cmdResp)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
