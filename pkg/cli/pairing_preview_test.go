// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDS34ConsumersCLI(t *testing.T) {
	for _, class := range []string{"autonomous", "session"} {
		rule, err := parseFirewallICSRuleArgs([]string{"r", "ALLOW", "dnp3", "--message-class", class, "--direction", "response"})
		if err != nil || rule.ICS.MessageClass != class {
			t.Fatalf("create selector: %+v %v", rule, err)
		}
		patch, err := parsePolicyRulePatch([]string{"--message-class", class}, true)
		if err != nil {
			t.Fatal(err)
		}
		assertPolicyJSON(t, patch, `{"ics":{"messageClass":"`+class+`"}}`)
		var shown bytes.Buffer
		renderFirewallICSRules(&shown, []config.Rule{rule}, "enforce")
		if !strings.Contains(shown.String(), "MESSAGE_CLASS") || !strings.Contains(shown.String(), class) {
			t.Fatal(shown.String())
		}
	}
	for _, value := range []string{"", "solicited", "unknown", "SESSION"} {
		if _, err := parseFirewallICSRuleArgs([]string{"r", "ALLOW", "dnp3", "--message-class", value}); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	clear, err := parsePolicyRulePatch([]string{"--message-class", ""}, true)
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyJSON(t, clear, `{"ics":{"messageClass":null}}`)
	response := map[string]any{"pairing": map[string]any{"unknown": 3, "reasons": []string{"pairing_unknown", "session_rule_required"}}}
	calls := 0
	api := &API{BaseURL: "http://local", Client: &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"POST /api/v1/firewall/rules/preview": func(req *http.Request) (*http.Response, error) {
			var rule config.Rule
			if err := json.NewDecoder(req.Body).Decode(&rule); err != nil {
				t.Fatal(err)
			}
			calls++ // read the complete body before recording the request
			if rule.ICS.MessageClass != "session" || req.Header.Get("X-Containd-If-Revision") != "" {
				t.Fatalf("preview mutation or lost selector: %+v", rule)
			}
			return jsonHTTPResponse(http.StatusOK, response, nil), nil
		},
		"GET /api/v1/dataplane/ruleset": func(req *http.Request) (*http.Response, error) {
			calls++
			return jsonHTTPResponse(http.StatusOK, response, nil), nil
		},
	}}}
	reg := NewRegistry(nil, api)
	for _, command := range []string{"preview firewall ics-rule r ALLOW dnp3 --message-class session --direction request", "preview firewall ruleset"} {
		var out bytes.Buffer
		if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), command, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "pairing_unknown") || !strings.Contains(out.String(), "session_rule_required") || strings.Contains(out.String(), stagedMessage) {
			t.Fatalf("preview reasons lost: %s", &out)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
