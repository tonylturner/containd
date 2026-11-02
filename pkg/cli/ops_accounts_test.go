// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func accountContext(password string) context.Context {
	return WithSecretPrompt(WithRole(context.Background(), "admin"), func(string) (string, error) {
		return password, nil
	})
}

func TestAccountSecretCommands(t *testing.T) {
	const password = "  Pässword1 \"\\\t "
	for _, tc := range []struct {
		name, path string
		args       []string
		want       map[string]string
	}{
		{"create user", "/api/v1/users", []string{"bob"}, map[string]string{"username": "bob", "role": "view", "password": password}},
		{"create user", "/api/v1/users", []string{"bob", "--role", "admin", "--first-name", "Bob B", "--last-name", "Smith", "--email", "bob@example.test"}, map[string]string{"username": "bob", "role": "admin", "firstName": "Bob B", "lastName": "Smith", "email": "bob@example.test", "password": password}},
		{"reset user password", "/api/v1/users/u%2F1/password", []string{"bob"}, map[string]string{"password": password}},
		{"reset user password", "/api/v1/users/u%2F1/password", []string{"u/1"}, map[string]string{"password": password}},
	} {
		t.Run(tc.name+strings.Join(tc.args, "-"), func(t *testing.T) {
			posts, gets := 0, 0
			api := &API{BaseURL: "http://appliance", Token: "token", Client: opsClient(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("X-Containd-If-Revision") != "" {
					t.Fatal("immediate account operation used configuration revision")
				}
				if r.Method == http.MethodGet {
					gets++
					if r.URL.Path != "/api/v1/users" {
						t.Fatalf("unexpected read: %s", r.URL)
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":"u/1","username":"bob"}]`))}, nil
				}
				var got map[string]string
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				posts++
				if r.Method != http.MethodPost || r.URL.RequestURI() != tc.path {
					t.Fatalf("unexpected mutation: %s %s", r.Method, r.URL)
				}
				if len(got) != len(tc.want) {
					t.Fatal("unexpected payload fields")
				}
				for k, v := range tc.want {
					if got[k] != v {
						t.Fatalf("field %s not preserved", k)
					}
				}
				// Neither a successful nor a failed reflected response is safe output.
				return &http.Response{StatusCode: 200, Header: http.Header{"X-Auth-Token": {"renewed"}}, Body: io.NopCloser(strings.NewReader(password))}, nil
			})}
			var out bytes.Buffer
			err := NewRegistry(nil, api).Execute(accountContext(password), tc.name, &out, tc.args)
			wantGets := 0
			if tc.name == "reset user password" {
				wantGets = 1
			}
			if err != nil || posts != 1 || gets != wantGets || api.Token != "renewed" {
				t.Fatalf("posts=%d gets=%d err=%v", posts, gets, err)
			}
			if strings.Contains(out.String(), password) || !strings.Contains(out.String(), "Applied immediately") {
				t.Fatal("unsafe or missing success output")
			}
		})
	}
}

func TestAccountSecretRefusals(t *testing.T) {
	for _, command := range []string{"create user", "reset user password"} {
		t.Run(command, func(t *testing.T) {
			calls, prompts := 0, 0
			api := &API{BaseURL: "http://appliance", Client: opsClient(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected HTTP")
			})}
			reg := NewRegistry(nil, api)
			prompt := func(string) (string, error) { prompts++; return "Password1", nil }
			if err := reg.Execute(WithSecretPrompt(context.Background(), prompt), command, io.Discard, []string{"bob"}); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("view permitted: %v", err)
			}
			if prompts != 0 {
				t.Fatal("view was asked for a secret")
			}
			for _, tc := range []struct {
				ctx  context.Context
				want string
			}{
				{WithRole(context.Background(), "admin"), ErrSecretInputUnavailable.Error()},
				{WithSecretPrompt(WithRole(context.Background(), "admin"), RefuseWebSecretInput), ErrWebSecretInput.Error()},
				{WithSecretPrompt(WithRole(context.Background(), "admin"), func(string) (string, error) {
					prompts++
					return strings.Repeat("x", prompts), nil
				}), "passwords do not match"},
				{accountContext(""), "cancelled"},
			} {
				err := reg.Execute(tc.ctx, command, io.Discard, []string{"bob"})
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("wanted %s, got %v", tc.want, err)
				}
			}
			if calls != 0 {
				t.Fatal("refused operation reached API")
			}
		})
	}
}

func TestCreateUserArgumentValidation(t *testing.T) {
	for _, args := range [][]string{
		nil, {""}, {"--role", "admin"}, {"bob", "--role"},
		{"bob", "--role", "root"}, {"bob", "--role", "admin", "--role", "view"},
		{"bob", "--password", "NeverAccept1"}, {"bob", "--unknown", "value"},
	} {
		ctx := WithSecretPrompt(WithRole(context.Background(), "admin"), func(string) (string, error) {
			t.Fatal("invalid command prompted for secret")
			return "", nil
		})
		if err := NewRegistry(nil, &API{}).Execute(ctx, "create user", io.Discard, args); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("invalid args accepted: %v", args)
		}
	}
}

func TestResetUserResolutionRefusesUnsafeTargets(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `[{"username":"bob"}]`, `[{"id":"u1","username":"bob"},{"id":"bob","username":"other"}]`, `invalid JSON`} {
		t.Run(body, func(t *testing.T) {
			gets := 0
			api := &API{BaseURL: "http://appliance", Client: opsClient(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/users" {
					t.Fatal("unsafe target mutated")
				}
				gets++
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			if err := NewRegistry(nil, api).Execute(accountContext("Password1"), "reset user password", io.Discard, []string{"bob"}); err == nil || gets != 1 {
				t.Fatalf("unsafe resolution: gets=%d err=%v", gets, err)
			}
		})
	}
}

func TestAccountSecretAPIErrorsNeverReflectResponse(t *testing.T) {
	for _, code := range []int{400, 401, 403, 409, 500} {
		api := &API{BaseURL: "http://appliance", Client: opsClient(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body))}, nil
		})}
		var out bytes.Buffer
		err := NewRegistry(nil, api).Execute(accountContext(" Password1 "), "create user", &out, []string{"bob"})
		if err == nil || strings.Contains(err.Error(), "Password1") || out.Len() != 0 || !strings.Contains(err.Error(), "account operation failed") {
			t.Fatalf("unsafe failure: %v", err)
		}
	}
}
