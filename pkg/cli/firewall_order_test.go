// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestFirewallOrderCommands(t *testing.T) {
	for _, words := range [][]string{{"top"}, {"bottom"}, {"before", "a"}, {"after", "b"}} {
		t.Run(strings.Join(words, " "), func(t *testing.T) {
			position, err := parseRulePosition(words)
			if err != nil {
				t.Fatal(err)
			}
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"POST /api/v1/firewall/rules/b/move": func(req *http.Request) (*http.Response, error) {
					body := decodeJSONRequest[map[string]any](t, req)
					if !reflect.DeepEqual(body["position"], jsonValue(t, position)) {
						t.Fatalf("move body=%v", body)
					}
					return jsonHTTPResponse(200, map[string]any{}, nil), nil
				},
				"POST /api/v1/firewall/rules": func(req *http.Request) (*http.Response, error) {
					body := decodeJSONRequest[map[string]json.RawMessage](t, req)
					var got any
					if json.Unmarshal(body["position"], &got) != nil || !reflect.DeepEqual(got, jsonValue(t, position)) {
						t.Fatalf("create body=%v", body)
					}
					delete(body, "position")
					data, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					var rule config.Rule
					if json.Unmarshal(data, &rule) != nil || rule.ID != "new" || !reflect.DeepEqual(rule.SourceZones, []string{"lan"}) || !reflect.DeepEqual(rule.DestZones, []string{"wan"}) {
						t.Fatalf("rule=%+v", rule)
					}
					return jsonHTTPResponse(200, map[string]any{}, nil), nil
				},
			}}
			api := &API{BaseURL: "http://localhost", Client: client}
			if err := moveFirewallRuleAPI(api)(context.Background(), nil, append([]string{"b"}, words...)); err != nil {
				t.Fatal(err)
			}
			if err := setFirewallRuleAPI(api)(context.Background(), nil, append([]string{"new", "allow", "lan", "wan"}, words...)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, words := range [][]string{nil, {"before"}, {"after", ""}, {"top", "extra"}, {"middle"}} {
		if _, err := parseRulePosition(words); err == nil {
			t.Fatalf("accepted position %v", words)
		}
	}
}

func TestPortForwardPublishDeleteOutput(t *testing.T) {
	for _, noAllow := range []bool{true, false} {
		client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
			"POST /api/v1/firewall/port-forwards": func(req *http.Request) (*http.Response, error) {
				body := decodeJSONRequest[struct {
					Forward config.PortForward `json:"forward"`
					Allow   bool               `json:"allowRule"`
				}](t, req)
				if body.Allow == noAllow || body.Forward.ID != "new" {
					t.Fatalf("body=%+v", body)
				}
				result := map[string]any{"forward": body.Forward}
				if !noAllow {
					result["placement"] = config.ForwardPlacement{Reason: "partial", RuleIDs: []string{"inspect"},
						Warning: &config.ForwardGrantWarning{Message: "No grant for sources any; backend 10.0.0.2:502"}}
				}
				return jsonHTTPResponse(200, result, nil), nil
			},
			"DELETE /api/v1/firewall/port-forwards/new": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(200, map[string]any{"deletedRuleIds": []string{"grant"}, "editedRuleIds": []string{"shared"}}, nil), nil
			},
		}}
		api := &API{BaseURL: "http://localhost", Client: client}
		args := []string{"new", "wan", "tcp", "1502", "10.0.0.2:502"}
		if noAllow {
			args = append(args, "no-allow")
		}
		var out bytes.Buffer
		if err := setPortForwardAddAPI(api)(context.Background(), &out, args); err != nil {
			t.Fatal(err)
		}
		if noAllow && !strings.Contains(out.String(), "No allow rule requested") || !noAllow && (!strings.Contains(out.String(), "inspect") || !strings.Contains(out.String(), "backend 10.0.0.2:502")) {
			t.Fatal(out.String())
		}
		out.Reset()
		if err := setPortForwardDelAPI(api)(context.Background(), &out, []string{"new"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "Deleted rules: grant") || !strings.Contains(out.String(), "Edited rules: shared") {
			t.Fatal(out.String())
		}
	}
	var out bytes.Buffer
	printForwardPlacement(&out, &config.ForwardPlacement{Rule: &config.Rule{ID: "generated"}, Index: 2})
	if !strings.Contains(out.String(), "generated at position 3") {
		t.Fatal(out.String())
	}
}

func TestFirewallRuleOrderOutput(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/firewall/rules": func(req *http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, []config.Rule{{ID: "z-first", Action: config.ActionDeny, ViaForwards: []string{"forward-z"}}, {ID: "a-last", Action: config.ActionAllow}}, nil), nil
		},
	}}
	var out bytes.Buffer
	if err := showFirewallRulesAPI(&API{BaseURL: "http://localhost", Client: client})(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "ORDER") || !strings.Contains(text, "VIA_FORWARDS") || !strings.Contains(text, "forward-z") || strings.Index(text, "z-first") > strings.Index(text, "a-last") {
		t.Fatal(text)
	}
}
