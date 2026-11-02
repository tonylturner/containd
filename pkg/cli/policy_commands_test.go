// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestPolicyRulePatchFields(t *testing.T) {
	args := []string{"--action", "rate_limit", "--source-zones", "lan,ops", "--dest-zones", "plant,dmz", "--sources", "10.0.0.0/24,10.2.0.0/16", "--destinations", "192.0.2.1/32", "--protocols", "tcp:502,udp:1000-2000,icmp", "--identities", "operator,engineer", "--via-forwards", "publish-1,publish-2", "--log", "false", "--rate-limit", "25:0", "--tag", "ot", "--description", "Maintenance window", "--schedule-days", "Monday,Tuesday", "--schedule-start", "09:00", "--schedule-end", "17:00", "--schedule-timezone", "America/New_York"}
	patch, err := parsePolicyRulePatch(args, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"RATE_LIMIT","sourceZones":["lan","ops"],"destZones":["plant","dmz"],"sources":["10.0.0.0/24","10.2.0.0/16"],"destinations":["192.0.2.1/32"],"protocols":[{"name":"tcp","port":"502"},{"name":"udp","port":"1000-2000"},{"name":"icmp"}],"identities":["operator","engineer"],"viaForwards":["publish-1","publish-2"],"log":false,"rateLimit":{"packetsPerSecond":25,"burst":0},"tag":"ot","description":"Maintenance window","schedule":{"daysOfWeek":["Monday","Tuesday"],"startTime":"09:00","endTime":"17:00","timezone":"America/New_York"}}`
	assertPolicyJSON(t, patch, want)
	patch, err = parsePolicyRulePatch([]string{"--source-zones", "", "--protocols", "", "--identities", "", "--schedule", "none", "--rate-limit", "none", "--tag", ""}, false)
	if err != nil {
		t.Fatal(err)
	}
	assertPolicyJSON(t, patch, `{"sourceZones":[],"protocols":[],"identities":[],"schedule":null,"rateLimit":null,"tag":""}`)
}

func assertPolicyJSON(t *testing.T, got any, want string) {
	t.Helper()
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	gotDecoder := json.NewDecoder(bytes.NewReader(data))
	gotDecoder.UseNumber()
	if err := gotDecoder.Decode(&g); err != nil {
		t.Fatal(err)
	}
	wantDecoder := json.NewDecoder(strings.NewReader(want))
	wantDecoder.UseNumber()
	if err := wantDecoder.Decode(&w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("got %s\nwant %s", data, want)
	}
}

func TestPolicyICSPartialSelectors(t *testing.T) {
	for flag, key := range policyICSKeys {
		t.Run(flag+" clear", func(t *testing.T) {
			patch, err := parsePolicyRulePatch([]string{flag, ""}, true)
			if err != nil {
				t.Fatal(err)
			}
			assertPolicyJSON(t, patch, `{"ics":{"`+key+`":null}}`)
		})
	}
	for _, tc := range []struct{ flag, value, want string }{
		{"--ics-protocol", "iec104", `{"protocol":"iec104"}`},
		{"--read-only", "false", `{"readOnly":false}`},
		{"--write-only", "true", `{"writeOnly":true}`},
		{"--unit-id", "0", `{"unitId":0}`},
		{"--function-code", "3,4", `{"functionCode":[3,4]}`},
		{"--object-classes", "4,0x66", `{"objectClasses":[4,102]}`},
		{"--addresses", "0-99,400-499", `{"addresses":["0-99","400-499"]}`},
		{"--mode", "enforce", `{"mode":"enforce"}`},
		{"--type-ids", "1,30", `{"typeIds":[1,30]}`},
		{"--classes", "monitor,control", `{"classes":["monitor","control"]}`},
		{"--ca", "0,1", `{"ca":[0,1]}`},
		{"--ioa", "10-20", `{"ioa":[{"start":10,"end":20}]}`},
		{"--direction", "response", `{"direction":"response"}`},
		{"--masters", "0,1", `{"masters":[0,1]}`},
		{"--outstations", "0,2", `{"outstations":[0,2]}`},
		{"--groups", "1", `{"groups":[1]}`},
		{"--variations", "0", `{"variations":[0]}`},
		{"--instances", "0", `{"instances":[0]}`},
		{"--attributes", "0", `{"attributes":[0]}`},
		{"--tags", "Motor.Speed", `{"tags":["Motor.Speed"]}`},
		{"--cot", "6", `{"cot":[6]}`},
		{"--originators", "0", `{"originators":[0]}`},
		{"--negative", "false", `{"negative":false}`},
		{"--test", "true", `{"test":true}`},
		{"--select-execute", "select", `{"selectExecute":"select"}`},
		{"--command-states", "1", `{"commandStates":[1]}`},
		{"--command-qualifiers", "0", `{"commandQualifiers":[0]}`},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			patch, err := parsePolicyRulePatch([]string{"--log", "false", tc.flag, tc.value}, true)
			if err != nil {
				t.Fatal(err)
			}
			assertPolicyJSON(t, patch, `{"log":false,"ics":`+tc.want+`}`)
		})
	}
}

func TestPolicyRuleCommandsUsePatchAndCAS(t *testing.T) {
	for _, command := range []string{"set firewall rule", "set firewall ics-rule"} {
		for _, status := range []int{200, 404, 412, 428} {
			t.Run(command+http.StatusText(status), func(t *testing.T) {
				reads, writes := 0, 0
				client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
					"GET /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) {
						reads++
						return jsonHTTPResponse(200, config.DefaultConfig(), map[string]string{"X-Containd-Revision": "0123456789abcdef.7"}), nil
					},
					"PATCH /api/v1/firewall/rules/existing": func(req *http.Request) (*http.Response, error) {
						body := decodeJSONRequest[map[string]any](t, req)
						writes++
						assertPolicyJSON(t, body, `{"log":false}`)
						if got := req.Header.Get("X-Containd-If-Revision"); got != "0123456789abcdef.7" {
							t.Fatalf("revision=%s", got)
						}
						return jsonHTTPResponse(status, map[string]any{"code": "config_revision_mismatch", "error": "changed", "currentRevision": "0123456789abcdef.8"}, map[string]string{"X-Containd-Config": "staged"}), nil
					},
				}}
				reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: client})
				var out bytes.Buffer
				err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), command+" existing --log false", &out)
				if status == 200 {
					if err != nil || !strings.Contains(out.String(), stagedMessage) {
						t.Fatalf("err=%v out=%s", err, &out)
					}
				} else if err == nil {
					t.Fatal("accepted failure")
				}
				if status == 412 || status == 428 {
					var failure *ConfigFailure
					if !errors.As(err, &failure) || failure.Status != status {
						t.Fatalf("error=%v", err)
					}
				}
				if reads != 1 || writes != 1 {
					t.Fatalf("reads=%d writes=%d (must not retry)", reads, writes)
				}
			})
		}
	}
}

func TestPolicyFocusedCandidateWrites(t *testing.T) {
	for _, tc := range []struct{ command, readPath, writePath, method, current, want string }{
		{"set firewall default deny", "/config/candidate", "/config/candidate", "POST", `{"firewall":{"rules":[{"id":"keep"}],"defaultAction":"ALLOW","identityBindings":[{"ip":"10.0.0.1"}],"future":9},"system":{"hostname":"keep"}}`, `{"firewall":{"rules":[{"id":"keep"}],"defaultAction":"DENY","identityBindings":[{"ip":"10.0.0.1"}],"future":9},"system":{"hostname":"keep"}}`},
		{"set zone consequence plant 'loss of cooling'", "/config/candidate", "/zones/plant", "PATCH", `{}`, `{"consequence":"loss of cooling"}`},
		{"set asset hostnames plc 'plc.example,backup.example'", "/assets", "/assets/plc", "PATCH", `[{"id":"plc","name":"PLC","ips":["10.0.0.1"],"tags":["safety"],"future":{"n":9007199254740993},"hostnames":["old"]}]`, `{"id":"plc","name":"PLC","ips":["10.0.0.1"],"tags":["safety"],"future":{"n":9007199254740993},"hostnames":["plc.example","backup.example"]}`},
		{"set asset hostnames plc ''", "/assets", "/assets/plc", "PATCH", `[{"id":"plc","name":"PLC","hostnames":["old"]}]`, `{"id":"plc","name":"PLC","hostnames":[]}`},
		{"set dataplane dpi enabled off", "/dataplane", "/dataplane", "POST", `{"dpiEnabled":true,"nfqueueGroup":101,"future":9007199254740993}`, `{"dpiEnabled":false,"nfqueueGroup":101,"future":9007199254740993}`},
		{"set dataplane dpi mode enforce", "/dataplane", "/dataplane", "POST", `{"dpiEnabled":true}`, `{"dpiEnabled":true,"dpiMode":"enforce"}`},
		{"set dataplane dpi protocols dns=false,http=true", "/dataplane", "/dataplane", "POST", `{"dpiProtocols":{"dns":true,"tls":false}}`, `{"dpiProtocols":{"dns":false,"tls":false,"http":true}}`},
		{"set dataplane dpi ics-protocols modbus=false", "/dataplane", "/dataplane", "POST", `{"dpiIcsProtocols":{"iec104":false}}`, `{"dpiIcsProtocols":{"iec104":false,"modbus":false}}`},
		{"set dataplane dpi ics-parsing modbus=strict", "/dataplane", "/dataplane", "POST", `{"dpiIcsParsing":{"iec104":"tolerant"}}`, `{"dpiIcsParsing":{"iec104":"tolerant","modbus":"strict"}}`},
		{"set dataplane dpi ics-protocols ''", "/dataplane", "/dataplane", "POST", `{"dpiIcsProtocols":{"iec104":false}}`, `{"dpiIcsProtocols":{}}`},
		{"set dataplane dpi exclusions ip:2001:db8::1,cidr:10.0.0.0/24,domain:example.org bypass", "/dataplane", "/dataplane", "POST", `{"dpiExclusions":[]}`, `{"dpiExclusions":[{"type":"ip","value":"2001:db8::1","reason":"bypass"},{"type":"cidr","value":"10.0.0.0/24","reason":"bypass"},{"type":"domain","value":"example.org","reason":"bypass"}]}`},
		{"set dataplane dpi exclusions ''", "/dataplane", "/dataplane", "POST", `{"dpiExclusions":[{"type":"ip","value":"10.0.0.1"}]}`, `{"dpiExclusions":[]}`},
		{"set dataplane nfqueue-group 65535", "/dataplane", "/dataplane", "POST", `{"nflogGroup":100}`, `{"nflogGroup":100,"nfqueueGroup":65535}`},
		{"set dataplane nflog-group 0", "/dataplane", "/dataplane", "POST", `{"nflogGroup":100,"nfqueueGroup":101}`, `{"nflogGroup":0,"nfqueueGroup":101}`},
	} {
		t.Run(tc.command, func(t *testing.T) {
			reads, writes := 0, 0
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET /api/v1" + tc.readPath: func(req *http.Request) (*http.Response, error) {
					reads++
					return jsonHTTPResponse(200, tc.current, map[string]string{"X-Containd-Revision": "0123456789abcdef.9"}), nil
				},
				tc.method + " /api/v1" + tc.writePath: func(req *http.Request) (*http.Response, error) {
					body := decodeJSONRequest[map[string]json.RawMessage](t, req)
					writes++
					assertPolicyJSON(t, body, tc.want)
					if got := req.Header.Get("X-Containd-If-Revision"); got != "0123456789abcdef.9" {
						t.Fatalf("revision=%s", got)
					}
					return jsonHTTPResponse(200, nil, map[string]string{"X-Containd-Config": "staged"}), nil
				},
			}}
			reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: client})
			var out bytes.Buffer
			if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), tc.command, &out); err != nil {
				t.Fatal(err)
			}
			if reads != 1 || writes != 1 || !strings.Contains(out.String(), stagedMessage) {
				t.Fatalf("reads=%d writes=%d out=%s", reads, writes, &out)
			}
		})
	}
}

func TestPolicyTemplateCommands(t *testing.T) {
	for _, preview := range []bool{true, false} {
		reads, writes := 0, 0
		client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/templates/ics": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(200, `[{"name":"modbus_register_guard","parameters":[{"name":"ranges","required":true}]}]`, nil), nil
			},
			"GET /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) { reads++; return jsonHTTPResponse(200, `{}`, nil), nil },
			"POST /api/v1/templates/ics/apply": func(req *http.Request) (*http.Response, error) {
				body := decodeJSONRequest[map[string]any](t, req)
				writes++
				if body["preview"] != preview || body["mode"] != "monitor" || body["template"] != "modbus_register_guard" {
					t.Fatalf("body=%v", body)
				}
				assertPolicyJSON(t, body["parameters"], `{"ranges":"0-99,400-499"}`)
				assertPolicyJSON(t, body["sourceZones"], `["ops","lan"]`)
				assertPolicyJSON(t, body["destZones"], `["plant"]`)
				if (req.Header.Get("X-Containd-If-Revision") == "") != preview {
					t.Fatal("wrong revision header")
				}
				headers := map[string]string{}
				if !preview {
					headers["X-Containd-Config"] = "staged"
				}
				return jsonHTTPResponse(200, `{"rules":[{"id":"generated"}]}`, headers), nil
			},
		}}
		reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: client})
		var out bytes.Buffer
		if err := reg.ParseAndExecute(context.Background(), "show templates ics", &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "parameters") {
			t.Fatal(out.String())
		}
		out.Reset()
		verb := "apply"
		if preview {
			verb = "preview"
		}
		if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), verb+" template ics modbus_register_guard --source-zones ops,lan --dest-zones plant --ranges 0-99,400-499 --mode monitor", &out); err != nil {
			t.Fatal(err)
		}
		if writes != 1 || preview && reads != 0 || !preview && reads != 1 {
			t.Fatalf("reads=%d writes=%d preview=%t", reads, writes, preview)
		}
		if preview && (!strings.Contains(out.String(), "generated") || strings.Contains(out.String(), stagedMessage)) {
			t.Fatal(out.String())
		}
		if !preview && !strings.Contains(out.String(), stagedMessage) {
			t.Fatal(out.String())
		}
	}
}

func TestPolicyRejectInvalidInputs(t *testing.T) {
	reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: policyNoRequestClient{t: t}})
	for _, line := range []string{
		"set firewall rule id ALLOW", "set firewall rule id --log", "set firewall rule id --log maybe", "set firewall rule id --unknown value", "set firewall rule id --rate-limit -1", "set firewall rule id --rate-limit 5:bad", "set firewall rule id --schedule tomorrow",
		"set firewall ics-rule id --read-only maybe", "set firewall ics-rule id --unit-id 256", "set firewall ics-rule id --ca 65535", "set firewall ics-rule id --mode unknown",
		"set firewall default", "set firewall default TAG", "set zone consequence plant", "set asset hostnames plc", "set dataplane nfqueue-group 65536", "set dataplane nflog-group -1",
		"set dataplane dpi", "set dataplane dpi enabled maybe", "set dataplane dpi mode learn", "set dataplane dpi ics-parsing modbus=bad", "set dataplane dpi protocols dns", "set dataplane dpi protocols dns=maybe", "set dataplane dpi exclusions ip:", "set dataplane dpi exclusions foo:bar", "set dataplane dpi enabled true extra", "set dataplane dpi unknown value",
		"apply template ics", "apply template ics name --mode", "apply template ics name --mode learn", "apply template ics name --unknown x", "show templates ics extra",
	} {
		t.Run(line, func(t *testing.T) {
			if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), line, io.Discard); err == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}

func TestPolicyCreationCutoverAndRoles(t *testing.T) {
	writes := 0
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"POST /api/v1/firewall/ics-rules": func(req *http.Request) (*http.Response, error) {
			rule := decodeJSONRequest[config.Rule](t, req)
			writes++
			if rule.ID != "new" || rule.ICS.Protocol != "modbus" || !rule.ICS.ReadOnly || req.Header.Get("X-Containd-If-Revision") == "" {
				t.Fatalf("rule=%+v headers=%v", rule, req.Header)
			}
			return jsonHTTPResponse(200, nil, nil), nil
		},
	}}
	reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: client})
	if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), "add firewall ics-rule new ALLOW modbus --read-only", io.Discard); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatal(writes)
	}
	for _, name := range []string{"set firewall rule", "set firewall ics-rule", "add firewall ics-rule", "set firewall default", "set zone consequence", "set asset hostnames", "set dataplane dpi", "set dataplane nfqueue-group", "set dataplane nflog-group", "apply template ics", "preview template ics"} {
		if err := reg.Execute(WithRole(context.Background(), "view"), name, io.Discard, nil); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestPolicyWritesFailClosed(t *testing.T) {
	for _, line := range []string{"set firewall default deny", "set asset hostnames plc plc.example", "set dataplane dpi enabled off", "apply template ics modbus_read_only"} {
		for _, failure := range []string{"stale", "missing revision", "null", "read failed"} {
			t.Run(line+failure, func(t *testing.T) {
				reads, writes := 0, 0
				read := func(req *http.Request) (*http.Response, error) {
					reads++
					headers := map[string]string{}
					body := `{"firewall":{"defaultAction":"ALLOW"}}`
					status := 200
					if strings.HasSuffix(req.URL.Path, "/assets") {
						body = `[{"id":"plc","name":"PLC"}]`
					}
					switch failure {
					case "missing revision":
						headers["X-Containd-Revision"] = ""
					case "null":
						body = "null"
					case "read failed":
						status = 503
					}
					return jsonHTTPResponse(status, body, headers), nil
				}
				write := func(req *http.Request) (*http.Response, error) {
					_ = decodeJSONRequest[json.RawMessage](t, req)
					writes++
					if failure != "stale" || req.Header.Get("X-Containd-If-Revision") == "" {
						t.Fatal("write without valid read")
					}
					return jsonHTTPResponse(412, `{"code":"config_revision_mismatch","error":"changed","currentRevision":"0123456789abcdef.2"}`, nil), nil
				}
				client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
					"GET /api/v1/config/candidate": read, "GET /api/v1/assets": read, "GET /api/v1/dataplane": read,
					"POST /api/v1/config/candidate": write, "PATCH /api/v1/assets/plc": write, "POST /api/v1/dataplane": write, "POST /api/v1/templates/ics/apply": write,
				}}
				reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: client})
				err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), line, io.Discard)
				if err == nil {
					t.Fatal("expected failure")
				}
				if reads != 1 || failure == "stale" && writes != 1 || failure != "stale" && writes != 0 {
					t.Fatalf("reads=%d writes=%d", reads, writes)
				}
			})
		}
	}
}

func TestPolicyAssetMissingAndEscapedRuleID(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/assets": func(req *http.Request) (*http.Response, error) { return jsonHTTPResponse(200, `[]`, nil), nil },
		"PATCH /api/v1/firewall/rules/rule /a": func(req *http.Request) (*http.Response, error) {
			_ = decodeJSONRequest[json.RawMessage](t, req)
			if req.URL.EscapedPath() != "/api/v1/firewall/rules/rule%20%2Fa" {
				t.Fatal(req.URL.EscapedPath())
			}
			return jsonHTTPResponse(200, nil, nil), nil
		},
	}}
	reg := NewRegistry(nil, &API{BaseURL: "http://localhost", Client: client})
	if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), "set asset hostnames absent plc.example", io.Discard); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error=%v", err)
	}
	if err := reg.ParseAndExecute(WithRole(context.Background(), "admin"), "set firewall rule 'rule /a' --log true", io.Discard); err != nil {
		t.Fatal(err)
	}
}

// Invalid arguments must fail before any transport call, not because of one.
type policyNoRequestClient struct{ t *testing.T }

func (c policyNoRequestClient) Do(req *http.Request) (*http.Response, error) {
	c.t.Helper()
	c.t.Fatalf("unexpected request for invalid command: %s %s", req.Method, req.URL)
	return nil, errors.New("unexpected request")
}
