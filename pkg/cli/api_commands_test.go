// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type dispatchHTTPClient struct {
	t        *testing.T
	handlers map[string]func(*http.Request) (*http.Response, error)
}

func (d *dispatchHTTPClient) Do(req *http.Request) (*http.Response, error) {
	d.t.Helper()
	key := req.Method + " " + req.URL.Path
	h, ok := d.handlers[key]
	if !ok {
		return nil, fmt.Errorf("unexpected request %s", key)
	}
	return h(req)
}

func jsonHTTPResponse(status int, body any, headers map[string]string) *http.Response {
	var payload []byte
	switch v := body.(type) {
	case nil:
		payload = []byte("{}")
	case string:
		payload = []byte(v)
	default:
		payload, _ = json.Marshal(v)
	}
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(payload)),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

func decodeJSONRequest[T any](t *testing.T, req *http.Request) T {
	t.Helper()
	var payload T
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return payload
}

func TestAPIPostMultipartFile(t *testing.T) {
	t.Parallel()

	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"POST /api/v1/upload": func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Get("Authorization"); got != "Bearer seed" {
					t.Fatalf("authorization header = %q", got)
				}
				reader, err := req.MultipartReader()
				if err != nil {
					t.Fatalf("multipart reader: %v", err)
				}
				part, err := reader.NextPart()
				if err != nil {
					t.Fatalf("next part: %v", err)
				}
				if part.FormName() != "file" || part.FileName() != "rules.txt" {
					t.Fatalf("unexpected multipart part: form=%q file=%q", part.FormName(), part.FileName())
				}
				body, err := io.ReadAll(part)
				if err != nil {
					t.Fatalf("read multipart body: %v", err)
				}
				if string(body) != "allow tcp/443" {
					t.Fatalf("unexpected multipart body: %q", string(body))
				}
				return jsonHTTPResponse(http.StatusOK, map[string]any{"id": "upload-1"}, map[string]string{"X-Auth-Token": "next"}), nil
			},
		},
	}

	api := &API{BaseURL: "http://localhost:8080", Client: client, Token: "seed"}
	var resp struct {
		ID string `json:"id"`
	}
	if err := api.postMultipartFile(context.Background(), "/api/v1/upload", "rules.txt", strings.NewReader("allow tcp/443"), &resp); err != nil {
		t.Fatalf("postMultipartFile: %v", err)
	}
	if resp.ID != "upload-1" {
		t.Fatalf("decoded response id = %q", resp.ID)
	}
	if api.Token != "next" {
		t.Fatalf("token not updated: %q", api.Token)
	}
}

func TestRoutingCommandsAndParsers(t *testing.T) {
	t.Parallel()

	if rt, err := parseRouteAddArgs([]string{"default", "via", "10.0.0.1", "dev", "wan", "table", "100", "metric", "5"}); err != nil {
		t.Fatalf("parseRouteAddArgs(valid): %v", err)
	} else if rt.Gateway != "10.0.0.1" || rt.Iface != "wan" || rt.Table != 100 || rt.Metric != 5 {
		t.Fatalf("unexpected route: %#v", rt)
	}
	if _, err := parseRouteAddArgs([]string{"default", "metric", "bad"}); err == nil {
		t.Fatal("expected invalid route metric error")
	}
	if rule, err := parseIPRuleAddArgs([]string{"100", "src", "10.0.0.0/24", "priority", "50"}); err != nil {
		t.Fatalf("parseIPRuleAddArgs(valid): %v", err)
	} else if rule.Table != 100 || rule.Src != "10.0.0.0/24" || rule.Priority != 50 {
		t.Fatalf("unexpected rule: %#v", rule)
	}
	if table, _, _, delAll, err := parseIPRuleDeleteArgs([]string{"100", "all"}); err != nil || !delAll || table != 100 {
		t.Fatalf("parseIPRuleDeleteArgs(all) = table=%d delAll=%v err=%v", table, delAll, err)
	}

	routing := config.RoutingConfig{
		Routes: []config.StaticRoute{{Dst: "default", Gateway: "10.0.0.1", Iface: "wan", Table: 100, Metric: 1}},
		Rules:  []config.PolicyRule{{Table: 100, Src: "10.0.0.0/24", Priority: 50}},
	}
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/routing": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, routing, nil), nil
			},
			"POST /api/v1/routing": func(req *http.Request) (*http.Response, error) {
				routing = decodeJSONRequest[config.RoutingConfig](t, req)
				return jsonHTTPResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	if err := setRouteAddAPI(api)(context.Background(), nil, []string{"10.1.0.0/24", "via", "10.0.0.2", "dev", "lan1"}); err != nil {
		t.Fatalf("setRouteAddAPI: %v", err)
	}
	if len(routing.Routes) != 2 {
		t.Fatalf("expected 2 routes after add, got %d", len(routing.Routes))
	}
	if err := setRouteDelAPI(api)(context.Background(), nil, []string{"10.1.0.0/24", "via", "10.0.0.2"}); err != nil {
		t.Fatalf("setRouteDelAPI: %v", err)
	}
	if len(routing.Routes) != 1 {
		t.Fatalf("expected 1 route after delete, got %d", len(routing.Routes))
	}
	if err := setIPRuleAddAPI(api)(context.Background(), nil, []string{"101", "src", "192.168.0.0/24", "priority", "70"}); err != nil {
		t.Fatalf("setIPRuleAddAPI: %v", err)
	}
	var buf bytes.Buffer
	if err := setIPRuleDelAPI(api)(context.Background(), &buf, []string{"101", "all"}); err != nil {
		t.Fatalf("setIPRuleDelAPI(all): %v", err)
	}
	if !strings.Contains(buf.String(), "Static routes:") || !strings.Contains(buf.String(), "Policy rules") {
		t.Fatalf("unexpected routing output: %q", buf.String())
	}
}

func TestSystemCommandsAndViews(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		System: config.SystemConfig{
			Hostname: "containd",
			Mgmt: config.MgmtConfig{
				ListenAddr:        ":8080",
				HTTPListenAddr:    ":8080",
				HTTPSListenAddr:   ":8443",
				RedirectHTTPToHTTPS: boolPtr(false),
			},
			SSH: config.SSHConfig{
				ListenAddr:        ":2222",
				AllowPassword:     true,
				AuthorizedKeysDir: "/data/ssh/authorized_keys.d",
			},
		},
		Interfaces: []config.Interface{{Name: "wan", Device: "eth0"}},
	}
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusInternalServerError, `{"error":"candidate missing"}`, nil), nil
			},
			"GET /api/v1/config": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, cfg, nil), nil
			},
			"GET /api/v1/config/export": func(req *http.Request) (*http.Response, error) {
				if req.URL.Query().Get("redacted") != "1" {
					t.Fatalf("expected redacted export query, got %q", req.URL.RawQuery)
				}
				return jsonHTTPResponse(http.StatusOK, cfg, nil), nil
			},
			"GET /api/v1/health": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, map[string]any{"component": "mgmt", "build": "0.1.x"}, nil), nil
			},
			"POST /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) {
				cfg = decodeJSONRequest[config.Config](t, req)
				return jsonHTTPResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	ctx := context.Background()

	if got, err := loadCandidateOrRunning(ctx, api); err != nil || got.System.Hostname != "containd" {
		t.Fatalf("loadCandidateOrRunning = %#v, %v", got, err)
	}
	if err := setSystemMgmtListenAPI(api)(ctx, nil, []string{":9090"}); err != nil {
		t.Fatalf("setSystemMgmtListenAPI: %v", err)
	}
	if err := setSystemMgmtHTTPListenAPI(api)(ctx, nil, []string{":9080"}); err != nil {
		t.Fatalf("setSystemMgmtHTTPListenAPI: %v", err)
	}
	if err := setSystemMgmtHTTPSListenAPI(api)(ctx, nil, []string{":9443"}); err != nil {
		t.Fatalf("setSystemMgmtHTTPSListenAPI: %v", err)
	}
	if err := setSystemMgmtEnableHTTPAPI(api)(ctx, nil, []string{"false"}); err != nil {
		t.Fatalf("setSystemMgmtEnableHTTPAPI: %v", err)
	}
	if err := setSystemMgmtEnableHTTPSAPI(api)(ctx, nil, []string{"true"}); err != nil {
		t.Fatalf("setSystemMgmtEnableHTTPSAPI: %v", err)
	}
	if err := setSystemMgmtRedirectHTTPToHTTPSAPI(api)(ctx, nil, []string{"true"}); err != nil {
		t.Fatalf("setSystemMgmtRedirectHTTPToHTTPSAPI: %v", err)
	}
	if err := setSystemMgmtHSTSAPI(api)(ctx, nil, []string{"true", "7200"}); err != nil {
		t.Fatalf("setSystemMgmtHSTSAPI: %v", err)
	}
	if err := setSystemSSHListenAPI(api)(ctx, nil, []string{":2022"}); err != nil {
		t.Fatalf("setSystemSSHListenAPI: %v", err)
	}
	if err := setSystemSSHAllowPasswordAPI(api)(ctx, nil, []string{"false"}); err != nil {
		t.Fatalf("setSystemSSHAllowPasswordAPI: %v", err)
	}
	if err := setSystemSSHAuthorizedKeysDirAPI(api)(ctx, nil, []string{"/keys"}); err != nil {
		t.Fatalf("setSystemSSHAuthorizedKeysDirAPI: %v", err)
	}
	if err := setSystemSSHBannerAPI(api)(ctx, nil, []string{"Authorized", "use", "only"}); err != nil {
		t.Fatalf("setSystemSSHBannerAPI: %v", err)
	}
	if err := setSystemSSHHostKeyRotationAPI(api)(ctx, nil, []string{"14"}); err != nil {
		t.Fatalf("setSystemSSHHostKeyRotationAPI: %v", err)
	}

	var listeners bytes.Buffer
	if err := showMgmtListeners(api)(ctx, &listeners, nil); err != nil {
		t.Fatalf("showMgmtListeners: %v", err)
	}
	if !strings.Contains(listeners.String(), "http_listen") || !strings.Contains(listeners.String(), ":9080") || !strings.Contains(listeners.String(), ":2022") {
		t.Fatalf("unexpected listeners output: %q", listeners.String())
	}
	var redacted bytes.Buffer
	if err := showRunningConfigRedacted(api)(ctx, &redacted, nil); err != nil {
		t.Fatalf("showRunningConfigRedacted: %v", err)
	}
	if !strings.Contains(redacted.String(), "\"hostname\": \"containd\"") {
		t.Fatalf("unexpected redacted config output: %q", redacted.String())
	}
}

func TestSyslogCommandsAndViews(t *testing.T) {
	t.Parallel()

	syslogCfg := map[string]any{
		"format": "rfc5424",
		"forwarders": []map[string]any{
			{"address": "192.0.2.10", "port": 514, "proto": "udp"},
		},
	}
	status := map[string]any{
		"syslog": map[string]any{
			"configured_forwarders": 1,
			"format":                "rfc5424",
			"protos":                "udp",
			"sent_total":            11,
			"failed_total":          1,
			"last_batch":            4,
			"batch_limit":           100,
			"last_flush":            "2026-03-13T12:00:00Z",
		},
	}
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"PATCH /api/v1/services/syslog": func(req *http.Request) (*http.Response, error) {
				var payload map[string]any
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatalf("decode syslog patch: %v", err)
				}
				switch payload["action"] {
				case nil:
					syslogCfg["format"] = payload["format"]
				case "add":
					fwd := payload["forwarder"].(map[string]any)
					syslogCfg["forwarders"] = append(syslogCfg["forwarders"].([]map[string]any), map[string]any{
						"address": fwd["address"],
						"port":    fwd["port"],
						"proto":   fwd["proto"],
					})
				case "del":
					syslogCfg["forwarders"] = []map[string]any{}
				default:
					t.Fatalf("unexpected action payload: %#v", payload)
				}
				return jsonHTTPResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			},
			"GET /api/v1/services/syslog": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, syslogCfg, nil), nil
			},
			"GET /api/v1/services/status": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, status, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	ctx := context.Background()

	if err := setSyslogFormatAPI(api)(ctx, nil, []string{"json"}); err != nil {
		t.Fatalf("setSyslogFormatAPI: %v", err)
	}
	if err := setSyslogForwarderAddAPI(api)(ctx, nil, []string{"198.51.100.10", "1514", "tcp"}); err != nil {
		t.Fatalf("setSyslogForwarderAddAPI: %v", err)
	}
	var cfgBuf bytes.Buffer
	if err := showSyslogConfig(api)(ctx, &cfgBuf, nil); err != nil {
		t.Fatalf("showSyslogConfig: %v", err)
	}
	if !strings.Contains(cfgBuf.String(), "format: json") || !strings.Contains(cfgBuf.String(), "198.51.100.10:1514 proto=tcp") {
		t.Fatalf("unexpected syslog config output: %q", cfgBuf.String())
	}
	if err := setSyslogForwarderDelAPI(api)(ctx, nil, []string{"198.51.100.10", "1514"}); err != nil {
		t.Fatalf("setSyslogForwarderDelAPI: %v", err)
	}
	var statusBuf bytes.Buffer
	if err := showSyslogStatus(api)(ctx, &statusBuf, nil); err != nil {
		t.Fatalf("showSyslogStatus: %v", err)
	}
	if !strings.Contains(statusBuf.String(), "sent_total: 11") || !strings.Contains(statusBuf.String(), "last_flush: 2026-03-13T12:00:00Z") {
		t.Fatalf("unexpected syslog status output: %q", statusBuf.String())
	}
}

func TestPortForwardCommandsAndViews(t *testing.T) {
	t.Parallel()

	if pf, err := parsePortForwardAddArgs([]string{"web", "wan", "tcp", "443", "10.0.0.10:8443", "sources", "192.0.2.0/24,192.0.2.0/24", "desc", "HTTPS", "off"}); err != nil {
		t.Fatalf("parsePortForwardAddArgs(valid): %v", err)
	} else if pf.Enabled || pf.DestPort != 8443 || len(pf.AllowedSources) != 1 {
		t.Fatalf("unexpected parsed port-forward: %#v", pf)
	}
	if _, err := parsePortForwardAddArgs([]string{"web", "wan", "icmp", "443", "10.0.0.10"}); err == nil {
		t.Fatal("expected invalid proto error")
	}

	nat := config.NATConfig{
		PortForwards: []config.PortForward{
			{ID: "ssh", Enabled: true, IngressZone: "wan", Proto: "tcp", ListenPort: 22, DestIP: "10.0.0.5", AllowedSources: []string{"203.0.113.0/24"}},
		},
	}
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/firewall/nat": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, nat, nil), nil
			},
			"POST /api/v1/firewall/nat": func(req *http.Request) (*http.Response, error) {
				nat = decodeJSONRequest[config.NATConfig](t, req)
				return jsonHTTPResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	ctx := context.Background()

	if err := setPortForwardAddAPI(api)(ctx, nil, []string{"web", "wan", "tcp", "443", "10.0.0.10:8443", "sources", "192.0.2.0/24", "desc", "HTTPS"}); err != nil {
		t.Fatalf("setPortForwardAddAPI: %v", err)
	}
	var out bytes.Buffer
	if err := showPortForwardsAPI(api)(ctx, &out, nil); err != nil {
		t.Fatalf("showPortForwardsAPI: %v", err)
	}
	if !strings.Contains(out.String(), "web") || !strings.Contains(out.String(), "10.0.0.10:8443") {
		t.Fatalf("unexpected port-forward output: %q", out.String())
	}
	if err := setPortForwardEnableAPI(api, false)(ctx, nil, []string{"web"}); err != nil {
		t.Fatalf("setPortForwardEnableAPI(disable): %v", err)
	}
	if err := setPortForwardDelAPI(api)(ctx, nil, []string{"web"}); err != nil {
		t.Fatalf("setPortForwardDelAPI: %v", err)
	}
}

func TestInterfaceAndTemplateCommands(t *testing.T) {
	t.Parallel()

	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/interfaces": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []config.Interface{
					{Name: "wan", Device: "eth6", Zone: "wan", AddressMode: "dhcp"},
					{Name: "lan1", Device: "eth0", Zone: "mgmt"},
				}, nil), nil
			},
			"GET /api/v1/interfaces/state": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []config.InterfaceState{
					{Name: "eth6", Index: 7, Up: true, MTU: 1500, MAC: "00:11:22:33:44:55", Addrs: []string{"192.168.240.2/24"}},
					{Name: "eth0", Index: 1, Up: true, MTU: 1500, MAC: "00:11:22:33:44:66", Addrs: []string{"192.168.241.2/24"}},
				}, nil), nil
			},
			"GET /api/v1/templates": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []map[string]any{{"name": "ics-baseline", "description": "OT starter rules"}}, nil), nil
			},
			"POST /api/v1/templates/apply": func(req *http.Request) (*http.Response, error) {
				payload := decodeJSONRequest[map[string]string](t, req)
				if payload["name"] != "ics-baseline" {
					t.Fatalf("unexpected template payload: %#v", payload)
				}
				return jsonHTTPResponse(http.StatusOK, map[string]any{"ok": true}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	var ifaces bytes.Buffer
	if err := showInterfacesAPI(api)(context.Background(), &ifaces, nil); err != nil {
		t.Fatalf("showInterfacesAPI: %v", err)
	}
	if !strings.Contains(ifaces.String(), "OS_ADDRS") || !strings.Contains(ifaces.String(), "192.168.240.2/24") || !strings.Contains(ifaces.String(), "Note: CONFIG_ADDRS") {
		t.Fatalf("unexpected interfaces output: %q", ifaces.String())
	}
	var state bytes.Buffer
	if err := showInterfacesStateAPI(api)(context.Background(), &state, nil); err != nil {
		t.Fatalf("showInterfacesStateAPI: %v", err)
	}
	if !strings.Contains(state.String(), "eth6") || !strings.Contains(state.String(), "00:11:22:33:44:55") {
		t.Fatalf("unexpected interface state output: %q", state.String())
	}
	var templates bytes.Buffer
	if err := showTemplatesAPI(api)(context.Background(), &templates, nil); err != nil {
		t.Fatalf("showTemplatesAPI: %v", err)
	}
	if !strings.Contains(templates.String(), "ics-baseline") {
		t.Fatalf("unexpected templates output: %q", templates.String())
	}
	if err := applyTemplateAPI(api)(context.Background(), nil, []string{"ics-baseline"}); err != nil {
		t.Fatalf("applyTemplateAPI: %v", err)
	}
}

func boolPtr(v bool) *bool { return &v }
