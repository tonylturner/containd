// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type opsClient func(*http.Request) (*http.Response, error)

func (f opsClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestOpsCommands(t *testing.T) {
	tests := []struct {
		name               string
		args               []string
		method, path, body string
		admin, immediate   bool
	}{
		{"show users", nil, "GET", "/api/v1/users", "", true, false},
		{"delete user", []string{"u1", "CONFIRM"}, "DELETE", "/api/v1/users/u1", "", true, true},
		{"require mfa user", []string{"u1", "CONFIRM"}, "POST", "/api/v1/users/u1/mfa/require", "{}", true, true},
		{"show backups", nil, "GET", "/api/v1/config/backups", "", false, false},
		{"create backup", []string{"before upgrade", "full", "CONFIRM"}, "POST", "/api/v1/config/backups", `{"name":"before upgrade","redacted":false}`, true, true},
		{"create backup", []string{"safe", "redacted", "CONFIRM"}, "POST", "/api/v1/config/backups", `{"name":"safe","redacted":true}`, true, true},
		{"delete backup", []string{"b1", "CONFIRM"}, "DELETE", "/api/v1/config/backups/b1", "", true, true},
		{"show openvpn clients", nil, "GET", "/api/v1/services/vpn/openvpn/clients", "", true, false},
		{"issue openvpn client", []string{"operator", "CONFIRM"}, "POST", "/api/v1/services/vpn/openvpn/clients", `{"name":"operator"}`, true, true},
		{"revoke openvpn client", []string{"c1", "CONFIRM"}, "POST", "/api/v1/services/vpn/openvpn/clients/c1/revoke", "{}", true, true},
		{"show protection", nil, "GET", "/api/v1/dataplane/protection", "", false, false},
		{"retry protection", []string{"boot", "apply", "CONFIRM"}, "POST", "/api/v1/dataplane/protection/retry", `{"applyId":"apply","bootId":"boot"}`, true, true},
		{"update av definitions", []string{"CONFIRM"}, "POST", "/api/v1/services/av/update", "", true, true},
		{"show pcap status", nil, "GET", "/api/v1/pcap/status", "", false, false},
		{"start pcap", []string{"CONFIRM"}, "POST", "/api/v1/pcap/start", "", true, true},
		{"stop pcap", []string{"CONFIRM"}, "POST", "/api/v1/pcap/stop", "", true, true},
		{"revoke connection", []string{"connection", "30", "tcp", "192.0.2.1", "192.0.2.2", "1234", "443", "CONFIRM"}, "POST", "/api/v1/conntrack/kill", `{"dport":443,"dst":"192.0.2.2","durationSecs":30,"proto":"tcp","scope":"connection","sport":1234,"src":"192.0.2.1"}`, true, true},
		{"revoke connection", []string{"client-service", "60", "icmpv6", "2001:db8::1", "2001:db8::2", "123", "128", "0", "CONFIRM"}, "POST", "/api/v1/conntrack/kill", `{"dst":"2001:db8::2","durationSecs":60,"icmpCode":0,"icmpId":123,"icmpType":128,"proto":"icmpv6","scope":"client-service","src":"2001:db8::1"}`, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name+strings.Join(tc.args, "-"), func(t *testing.T) {
			calls := 0
			api := &API{BaseURL: "http://appliance", Token: "session", Client: opsClient(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				calls++
				if r.Method != tc.method || r.URL.RequestURI() != tc.path || string(body) != tc.body {
					t.Fatalf("request %s %s %s", r.Method, r.URL, body)
				}
				if r.Header.Get("Authorization") != "Bearer session" || r.Header.Get("X-Containd-If-Revision") != "" {
					t.Fatalf("headers: %v", r.Header)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"X-Auth-Token": []string{"renewed"}}, Body: io.NopCloser(strings.NewReader(`{"state":"unknown","cause":"runtime unavailable"}`))}, nil
			})}
			registry := NewRegistry(nil, api)
			ctx := context.Background()
			if tc.admin {
				if err := registry.Execute(ctx, tc.name, io.Discard, tc.args); !errors.Is(err, ErrPermissionDenied) || calls != 0 {
					t.Fatalf("view allowed mutation: %v", err)
				}
			}
			if tc.immediate {
				if err := registry.Execute(WithRole(ctx, "admin"), tc.name, io.Discard, tc.args[:len(tc.args)-1]); err == nil || calls != 0 {
					t.Fatal("unconfirmed operation sent")
				}
			}
			var out bytes.Buffer
			if err := registry.Execute(WithRole(ctx, "admin"), tc.name, &out, tc.args); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || api.Token != "renewed" {
				t.Fatalf("calls=%d token=%s", calls, api.Token)
			}
			if !strings.Contains(out.String(), "runtime unavailable") || !strings.Contains(out.String(), "unknown") {
				t.Fatalf("lost state/cause: %s", &out)
			}
			if strings.Contains(out.String(), "Immediate") != tc.immediate {
				t.Fatalf("immediate notice: %s", &out)
			}
		})
	}
}

func TestOpsDownloads(t *testing.T) {
	for _, name := range []string{"download backup", "download openvpn client"} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "download")
			api := &API{BaseURL: "http://appliance", Client: opsClient(func(r *http.Request) (*http.Response, error) {
				want := "/api/v1/config/backups/a%2Fb"
				if name == "download openvpn client" {
					want = "/api/v1/services/vpn/openvpn/clients/a%2Fb"
				}
				if r.URL.EscapedPath() != want {
					t.Fatalf("path %s", r.URL.EscapedPath())
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("private-data"))}, nil
			})}
			registry := NewRegistry(nil, api)
			var out bytes.Buffer
			args := []string{"a/b", file}
			ctx := WithLocalFilesystem(context.Background(), true)
			if err := registry.Execute(WithRole(ctx, "view"), name, &out, args); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("viewer download allowed: %v", err)
			}
			if err := registry.Execute(WithRole(ctx, "admin"), name, &out, args); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(file)
			if err != nil || string(data) != "private-data" {
				t.Fatalf("data %s: %v", data, err)
			}
			stat, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			if stat.Mode().Perm() != 0o600 {
				t.Fatalf("permissions %v", stat.Mode())
			}
			if strings.Contains(out.String(), "private-data") {
				t.Fatal("secret rendered")
			}
			if err := registry.Execute(WithRole(ctx, "admin"), name, &out, args); err == nil {
				t.Fatal("overwrote existing file")
			}
		})
	}
}

func TestOpsErrorsPreservePartialResults(t *testing.T) {
	for _, status := range []int{400, 403, 409, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			api := &API{BaseURL: "http://appliance", Client: opsClient(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"revoked":true,"applied":false,"error":"runtime not confirmed"}`))}, nil
			})}
			var out bytes.Buffer
			err := NewRegistry(nil, api).Execute(WithRole(context.Background(), "admin"), "revoke openvpn client", &out, []string{"c1", "CONFIRM"})
			if err == nil || !strings.Contains(err.Error(), `"revoked":true`) || !strings.Contains(err.Error(), "runtime not confirmed") {
				t.Fatalf("lost partial result: %v", err)
			}
			if strings.Contains(out.String(), "ok") || strings.Contains(out.String(), "staged;") {
				t.Fatalf("claimed success: %s", &out)
			}
		})
	}
}

func TestOpsMalformedReadIsNotOff(t *testing.T) {
	for _, body := range []string{"null", "not JSON"} {
		api := &API{BaseURL: "http://appliance", Client: opsClient(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		if err := opsRead(api, "/status")(context.Background(), io.Discard, nil); err == nil {
			t.Fatal("malformed read accepted")
		}
	}
}

func TestOpsExportModes(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		query string
	}{
		{nil, ""}, {[]string{"redacted"}, "redacted=1"}, {[]string{"--redacted"}, "redacted=1"}, {[]string{"full"}, "redacted=0"},
	} {
		t.Run(strings.Join(tc.args, "-"), func(t *testing.T) {
			calls := 0
			api := &API{BaseURL: "http://appliance", Client: opsClient(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/api/v1/config/export" || r.URL.RawQuery != tc.query {
					t.Fatalf("wrong export: %s", r.URL)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"description":"exported"}`))}, nil
			})}
			if err := NewRegistry(nil, api).Execute(WithRole(context.Background(), "admin"), "export config", io.Discard, tc.args); err != nil || calls != 1 {
				t.Fatalf("export: %v calls=%d", err, calls)
			}
			if err := NewRegistry(nil, api).Execute(context.Background(), "export config", io.Discard, tc.args); !errors.Is(err, ErrPermissionDenied) || calls != 1 {
				t.Fatalf("view export allowed: %v", err)
			}
		})
	}
	api := &API{Client: opsClient(func(*http.Request) (*http.Response, error) { t.Fatal("invalid export reached API"); return nil, nil })}
	for _, args := range [][]string{{"ful"}, {"full", "extra"}} {
		if err := exportConfigAPI(api)(WithRole(context.Background(), "admin"), io.Discard, args); err == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
}

func TestOpsReadErrorRetainsCause(t *testing.T) {
	api := &API{BaseURL: "http://appliance", Client: opsClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"engine unavailable"}`))}, nil
	})}
	var out bytes.Buffer
	err := opsRead(api, "/status")(context.Background(), &out, nil)
	if err == nil || !strings.Contains(err.Error(), "engine unavailable") || out.Len() != 0 {
		t.Fatalf("error=%v output=%s", err, &out)
	}
}
