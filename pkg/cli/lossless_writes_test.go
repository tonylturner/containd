// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Use complete subtrees, including settings the commands cannot edit.
const losslessConfig = `{
	"system":{"hostname":"candidate","mgmt":{"listenAddr":":8080","httpListenAddr":":8080",
		"httpsListenAddr":":8443","enableHttp":true,"enableHttps":true,
		"redirectHttpToHttps":false,"enableHsts":false,"hstsMaxAgeSeconds":123,
		"tlsCertFile":"/cert","tlsKeyFile":"/key","trustedCaFile":"/ca"},
		"ssh":{"listenAddr":":2222","allowPassword":true,"authorizedKeysDir":"/keys",
			"banner":"hello","hostKeyRotationDays":7,"shellMode":"appliance"}},
	"interfaces":[{"name":"wan","zone":"wan","device":"eth0","alias":"uplink",
		"type":"vlan","parent":"eth1","vlanId":42,"members":["eth2"],
		"addressMode":"static","gateway":"192.0.2.1",
		"addresses":["192.0.2.7/24"],"access":{"ssh":false}}],
	"zones":[{"name":"wan","alias":"outside","slTarget":2,"consequence":"high"}],
	"firewall":{"defaultAction":"DENY","nat":{"enabled":true,"egressZone":"outside",
		"sourceZones":["inside"],"portForwards":[
		{"id":"keep","enabled":true,"ingressZone":"wan","proto":"tcp","listenPort":443,
			"destIp":"192.0.2.9","destPort":8443,"allowedSources":["198.51.100.0/24"],"description":"keep"},
		{"id":"edit","enabled":true,"ingressZone":"wan","proto":"udp","listenPort":53,
			"destIp":"192.0.2.10","destPort":5353,"allowedSources":["203.0.113.0/24"],"description":"edit"}
	]},
	"rules":[{"id":"allow-lan-mgmt-wan","action":"DENY","description":"old",
		"sourceZones":["dmz"],"destZones":["lan"],"sources":["192.0.2.0/24"],
		"destinations":["203.0.113.0/24"],"protocols":[{"name":"tcp","port":"443"}],
		"identities":["operator"],"tag":"retain","log":true,"ics":{"protocol":"modbus","readOnly":true},
		"rateLimit":{"packetsPerSecond":10},"schedule":{"timezone":"UTC","startTime":"09:00"}}]},
	"routing":{"gateways":[{"name":"wan-gw","address":"192.0.2.254","iface":"old",
		"alias":"retain-alias","description":"old"}],
		"routes":[{"dst":"default","gateway":"wan-gw","iface":"old","metric":42},
			{"dst":"198.18.0.0/15","gateway":"192.0.2.2","table":100,"metric":7}],
		"rules":[{"table":100,"src":"198.18.0.0/15","dst":"203.0.113.0/24","priority":11},
			{"table":200,"src":"192.0.2.0/24","priority":12}]},
	"dataplane":{"enforcement":true,"enforceTable":"keep","captureInterfaces":["eth0"],
		"dpiEnabled":true,"dpiMode":"monitor","dpiMock":true,
		"dpiProtocols":{"dns":true},"dpiIcsProtocols":{"modbus":false},
		"dpiIcsParsing":{"iec104":"strict"},"nflogGroup":12,"nfqueueGroup":13,
		"dpiExclusions":[{"type":"cidr","value":"192.0.2.0/24","reason":"retain"}]},
	"services":{"syslog":{"format":"json","batchSize":12,"flushEvery":3,
		"forwarders":[{"address":"logs","port":514,"proto":"tcp"}]},
		"proxy":{"forward":{"enabled":true,"listenPort":3129,"listenZones":["inside"],
			"allowedClients":["client"],"allowedDomains":["example.test"],"upstream":"http://upstream:3128",
			"logRequests":true},
			"reverse":{"enabled":true,"sites":[{"name":"site","listenPort":443,"hostnames":["example.test"],
				"backends":["192.0.2.8:8443"],"tlsEnabled":true,"certRef":"cert","description":"retain"}]}},
		"dns":{"enabled":true,"upstreamServers":["192.0.2.53"]},
		"vpn":{"wireguard":{"enabled":true,"privateKey":"retain","peers":[{"publicKey":"peer","allowedIPs":["10.0.0.0/24"]}]}}},
	"ids":{"enabled":true,"ruleGroups":[{"id":"retain","name":"group","enabled":true}]}
}`

func losslessFixture(t *testing.T) config.Config {
	t.Helper()
	var cfg config.Config
	decoder := json.NewDecoder(strings.NewReader(losslessConfig))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func jsonValue(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type losslessCase struct {
	name, path        string
	method, writePath string
	command           func(*API) Command
	args              []string
	current, want     any
}

func losslessCases(t *testing.T) []losslessCase {
	t.Helper()
	var cases []losslessCase
	add := func(name, path string, command func(*API) Command, args []string,
		subtree func(config.Config) any, edit func(*config.Config)) {
		current, want := losslessFixture(t), losslessFixture(t)
		edit(&want)
		cases = append(cases, losslessCase{
			name: name, path: path, method: http.MethodPost, writePath: path,
			command: command, args: args, current: subtree(current), want: subtree(want),
		})
	}
	nat := func(c config.Config) any { return c.Firewall.NAT }
	add("nat toggle", "/api/v1/firewall/nat", setNATAPI, []string{"off"}, nat,
		func(c *config.Config) { c.Firewall.NAT.Enabled = false })
	add("nat options", "/api/v1/firewall/nat", setNATAPI, []string{"on", "egress", "wan", "sources", "lan,mgmt"}, nat,
		func(c *config.Config) {
			c.Firewall.NAT.EgressZone = "wan"
			c.Firewall.NAT.SourceZones = []string{"lan", "mgmt"}
		})
	add("nat defaults", "/api/v1/firewall/nat", setNATAPI, []string{"off", "egress", "default", "sources", "default"}, nat,
		func(c *config.Config) {
			c.Firewall.NAT.Enabled = false
			c.Firewall.NAT.EgressZone = ""
			c.Firewall.NAT.SourceZones = nil
		})
	for _, enabled := range []bool{true, false} {
		add(fmt.Sprintf("port-forward enabled=%v", enabled), "/api/v1/firewall/nat",
			func(api *API) Command { return setPortForwardEnableAPI(api, enabled) }, []string{"edit"}, nat,
			func(c *config.Config) { c.Firewall.NAT.PortForwards[1].Enabled = enabled })
	}
	forward := func(c config.Config) any { return c.Services.Proxy.Forward }
	add("forward toggle", "/api/v1/services/proxy/forward", setForwardProxyAPI, []string{"off"}, forward,
		func(c *config.Config) { c.Services.Proxy.Forward.Enabled = false })
	add("forward port", "/api/v1/services/proxy/forward", setForwardProxyAPI, []string{"on", "8080"}, forward,
		func(c *config.Config) { c.Services.Proxy.Forward.ListenPort = 8080 })
	add("forward zones", "/api/v1/services/proxy/forward", setForwardProxyAPI, []string{"on", "8080", "lan", "mgmt"}, forward,
		func(c *config.Config) {
			c.Services.Proxy.Forward.ListenPort = 8080
			c.Services.Proxy.Forward.ListenZones = []string{"lan", "mgmt"}
		})
	add("reverse toggle", "/api/v1/services/proxy/reverse", setReverseProxyAPI, []string{"off"},
		func(c config.Config) any { return c.Services.Proxy.Reverse },
		func(c *config.Config) { c.Services.Proxy.Reverse.Enabled = false })
	add("dataplane", "/api/v1/dataplane", setDataPlaneAPI, []string{"enforcement", "off"},
		func(c config.Config) any { return c.DataPlane },
		func(c *config.Config) { c.DataPlane.Enforcement = false })
	routing := func(c config.Config) any { return c.Routing }
	add("route add", "/api/v1/routing", setRouteAddAPI, []string{"203.0.113.0/24", "via", "192.0.2.1"}, routing,
		func(c *config.Config) {
			c.Routing.Routes = append(c.Routing.Routes, config.StaticRoute{Dst: "203.0.113.0/24", Gateway: "192.0.2.1"})
		})
	add("route del", "/api/v1/routing", setRouteDelAPI, []string{"default"}, routing,
		func(c *config.Config) { c.Routing.Routes = c.Routing.Routes[1:] })
	add("ip rule add", "/api/v1/routing", setIPRuleAddAPI, []string{"123", "src", "192.0.2.0/24"}, routing,
		func(c *config.Config) {
			c.Routing.Rules = append(c.Routing.Rules, config.PolicyRule{Table: 123, Src: "192.0.2.0/24"})
		})
	for _, args := range [][]string{{"100", "src", "198.18.0.0/15"}, {"100", "all"}} {
		add("ip rule del "+strings.Join(args, " "), "/api/v1/routing", setIPRuleDelAPI, args, routing,
			func(c *config.Config) { c.Routing.Rules = c.Routing.Rules[1:] })
	}
	whole := func(c config.Config) any { return c }
	system := func(name string, command func(*API) Command, args []string, edit func(*config.Config)) {
		add(name, "/api/v1/config/candidate", command, args, whole, edit)
	}
	system("hostname", setSystemHostnameAPI, []string{"new"}, func(c *config.Config) { c.System.Hostname = "new" })
	system("mgmt listen", setSystemMgmtListenAPI, []string{":9090"}, func(c *config.Config) { c.System.Mgmt.ListenAddr = ":9090" })
	system("http listen", setSystemMgmtHTTPListenAPI, []string{":9090"}, func(c *config.Config) { c.System.Mgmt.HTTPListenAddr = ":9090" })
	system("https listen", setSystemMgmtHTTPSListenAPI, []string{":9443"}, func(c *config.Config) { c.System.Mgmt.HTTPSListenAddr = ":9443" })
	system("http enable", setSystemMgmtEnableHTTPAPI, []string{"false"}, func(c *config.Config) { c.System.Mgmt.EnableHTTP = new(false) })
	system("https enable", setSystemMgmtEnableHTTPSAPI, []string{"false"}, func(c *config.Config) { c.System.Mgmt.EnableHTTPS = new(false) })
	system("redirect", setSystemMgmtRedirectHTTPToHTTPSAPI, []string{"true"}, func(c *config.Config) { c.System.Mgmt.RedirectHTTPToHTTPS = new(true) })
	system("hsts", setSystemMgmtHSTSAPI, []string{"true", "456"}, func(c *config.Config) { c.System.Mgmt.EnableHSTS = new(true); c.System.Mgmt.HSTSMaxAgeSeconds = 456 })
	system("ssh listen", setSystemSSHListenAPI, []string{":2223"}, func(c *config.Config) { c.System.SSH.ListenAddr = ":2223" })
	system("ssh password", setSystemSSHAllowPasswordAPI, []string{"false"}, func(c *config.Config) { c.System.SSH.AllowPassword = new(false) })
	system("ssh keys", setSystemSSHAuthorizedKeysDirAPI, []string{"/new"}, func(c *config.Config) { c.System.SSH.AuthorizedKeysDir = "/new" })
	system("ssh banner", setSystemSSHBannerAPI, []string{"new", "banner"}, func(c *config.Config) { c.System.SSH.Banner = "new banner" })
	system("ssh rotation", setSystemSSHHostKeyRotationAPI, []string{"14"}, func(c *config.Config) { c.System.SSH.HostKeyRotationDays = 14 })
	system("ssh shell", setSystemSSHShellModeAPI, []string{"linux"}, func(c *config.Config) { c.System.SSH.ShellMode = "linux" })
	for _, tc := range []struct {
		name    string
		command func(*API) Command
		args    []string
		patch   map[string]any
	}{
		{"interface bind", setInterfaceBindAPI, []string{"wan", "eth3"}, map[string]any{"device": "eth3"}},
		{"interface zone", setInterfaceZoneAPI, []string{"wan", "dmz"}, map[string]any{"zone": "dmz"}},
		{"interface dhcp", setInterfaceIPAPI, []string{"wan", "dhcp"}, map[string]any{"addressMode": "dhcp", "addresses": []any{}, "gateway": ""}},
		{"interface static", setInterfaceIPAPI, []string{"wan", "static", "192.0.2.8/24", "192.0.2.2"}, map[string]any{"addressMode": "static", "addresses": []any{"192.0.2.8/24"}, "gateway": "192.0.2.2"}},
		{"interface addresses", setInterfaceIPAPI, []string{"wan", "192.0.2.8/24", "198.51.100.1/24"}, map[string]any{"addressMode": "static", "addresses": []any{"192.0.2.8/24", "198.51.100.1/24"}, "gateway": ""}},
		{"interface clear", setInterfaceIPAPI, []string{"wan", "none"}, map[string]any{"addressMode": "static", "addresses": []any{}, "gateway": ""}},
	} {
		current := losslessFixture(t).Interfaces
		cases = append(cases, losslessCase{
			name: tc.name, path: "/api/v1/interfaces", method: http.MethodPatch, writePath: "/api/v1/interfaces/wan",
			command: tc.command, args: tc.args, current: current, want: tc.patch,
		})
	}
	return cases
}

type recordedWrite struct {
	method, path string
	body         any
}

// Read bodies before recording requests, even when the client later cancels.
type configFake struct {
	counter  int
	mu       sync.Mutex
	reads    map[string]any
	failPath string
	status   int
	body     string
	requests []string
	writes   []recordedWrite
}

func (f *configFake) serve(w http.ResponseWriter, r *http.Request) {
	var body any
	if r.Method != http.MethodGet {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if f.counter == 0 {
		f.counter = 1
	}
	revision := fmt.Sprintf("0123456789abcdef.%d", f.counter)
	w.Header().Set("X-Containd-Revision", revision)
	if r.Method == http.MethodGet {
		if r.URL.Path == f.failPath {
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, f.body)
			return
		}
		v, ok := f.reads[r.URL.Path]
		if !ok {
			http.Error(w, "unexpected read", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	if r.Header.Get("X-Containd-If-Revision") != revision {
		http.Error(w, "wrong revision", http.StatusPreconditionFailed)
		return
	}
	f.counter++
	w.Header().Set("X-Containd-Revision", fmt.Sprintf("0123456789abcdef.%d", f.counter))
	f.writes = append(f.writes, recordedWrite{r.Method, r.URL.Path, body})
	if r.Method == http.MethodPost {
		f.reads[r.URL.Path] = body
	}
	_, _ = io.WriteString(w, "{}")
}

func TestConfigWritesPreserveSubtrees(t *testing.T) {
	for _, tc := range losslessCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			fake := &configFake{reads: map[string]any{tc.path: tc.current}}
			server := httptest.NewServer(http.HandlerFunc(fake.serve))
			defer server.Close()
			api := &API{BaseURL: server.URL, Client: server.Client()}
			if err := tc.command(api)(context.Background(), io.Discard, tc.args); err != nil {
				t.Fatal(err)
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			want := []recordedWrite{{tc.method, tc.writePath, jsonValue(t, tc.want)}}
			if !reflect.DeepEqual(fake.writes, want) {
				t.Fatalf("writes = %#v\nwant = %#v", fake.writes, want)
			}
		})
	}
}

var failedConfigReads = []struct {
	name   string
	status int
	body   string
}{
	{"status", http.StatusServiceUnavailable, `{"error":"unavailable"}`},
	{"missing", http.StatusNotFound, `{"error":"not found"}`},
	{"null", http.StatusOK, "null"},
	{"empty", http.StatusOK, ""},
	{"malformed", http.StatusOK, `{"enabled":`},
	{"wrong type", http.StatusOK, `"not a config"`},
}

func TestConfigWritesStopOnReadFailure(t *testing.T) {
	for _, tc := range losslessCases(t) {
		for _, failure := range failedConfigReads {
			t.Run(tc.name+"/"+failure.name, func(t *testing.T) {
				fake := &configFake{
					// Running data must never substitute for an unavailable candidate.
					reads:    map[string]any{"/api/v1/config": losslessFixture(t)},
					failPath: tc.path, status: failure.status, body: failure.body,
				}
				server := httptest.NewServer(http.HandlerFunc(fake.serve))
				defer server.Close()
				err := tc.command(&API{BaseURL: server.URL, Client: server.Client()})(context.Background(), io.Discard, tc.args)
				if err == nil || !strings.Contains(err.Error(), "cannot read current config from "+tc.path) {
					t.Fatalf("expected contextual read error, got %v", err)
				}
				fake.mu.Lock()
				defer fake.mu.Unlock()
				if len(fake.writes) != 0 || !reflect.DeepEqual(fake.requests, []string{"GET " + tc.path}) {
					t.Fatalf("unexpected requests: %v; writes: %v", fake.requests, fake.writes)
				}
			})
		}
	}
}

func TestConfigWritesStopOnTransportFailure(t *testing.T) {
	for _, tc := range losslessCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			var requests []string
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET " + tc.path: func(r *http.Request) (*http.Response, error) {
					requests = append(requests, r.Method+" "+r.URL.Path)
					return nil, fmt.Errorf("network unavailable")
				},
				tc.method + " " + tc.writePath: func(r *http.Request) (*http.Response, error) {
					_, _ = io.Copy(io.Discard, r.Body)
					t.Error("write after transport failure")
					return jsonHTTPResponse(http.StatusOK, "{}", nil), nil
				},
			}}
			err := tc.command(&API{BaseURL: "http://test", Client: client})(context.Background(), io.Discard, tc.args)
			if err == nil || !strings.Contains(err.Error(), "network unavailable") {
				t.Fatalf("expected transport error, got %v", err)
			}
			if !reflect.DeepEqual(requests, []string{"GET " + tc.path}) {
				t.Fatalf("requests = %v", requests)
			}
		})
	}
}

func TestConfigWritesRepeatedProxyEdits(t *testing.T) {
	const path = "/api/v1/services/proxy/forward"
	current := losslessFixture(t).Services.Proxy.Forward
	fake := &configFake{reads: map[string]any{path: current}}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	defer server.Close()
	command := setForwardProxyAPI(&API{BaseURL: server.URL, Client: server.Client()})
	for _, args := range [][]string{{"on", "8080", "dmz"}, {"off"}} {
		if err := command(context.Background(), io.Discard, args); err != nil {
			t.Fatal(err)
		}
	}
	current.ListenPort = 8080
	current.ListenZones = []string{"dmz"}
	first := current
	current.Enabled = false
	want := []recordedWrite{
		{http.MethodPost, path, jsonValue(t, first)},
		{http.MethodPost, path, jsonValue(t, current)},
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !reflect.DeepEqual(fake.writes, want) {
		t.Fatalf("writes = %#v\nwant = %#v", fake.writes, want)
	}
}

func TestInterfaceEditRequiresExistingInterface(t *testing.T) {
	fake := &configFake{reads: map[string]any{"/api/v1/interfaces": []config.Interface{}}}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	defer server.Close()
	err := setInterfaceBindAPI(&API{BaseURL: server.URL, Client: server.Client()})(context.Background(), io.Discard, []string{"missing", "eth0"})
	if err == nil || err.Error() != "interface not found: missing" {
		t.Fatalf("expected missing interface error, got %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.writes) != 0 {
		t.Fatalf("unexpected writes: %v", fake.writes)
	}
}

func quickstartReads(c config.Config) map[string]any {
	return map[string]any{
		"/api/v1/config/candidate": c,
		"/api/v1/interfaces/state": []outboundIfaceState{{Name: "eth0", Addrs: []string{"192.0.2.7/24"}}},
	}
}

func TestQuickstartStopsBeforeAnyWriteOnReadFailure(t *testing.T) {
	for path := range quickstartReads(losslessFixture(t)) {
		for _, failure := range failedConfigReads {
			t.Run(path+"/"+failure.name, func(t *testing.T) {
				fake := &configFake{
					reads:    quickstartReads(losslessFixture(t)),
					failPath: path, status: failure.status, body: failure.body,
				}
				server := httptest.NewServer(http.HandlerFunc(fake.serve))
				defer server.Close()
				err := setOutboundQuickstartLANWAN(&API{BaseURL: server.URL, Client: server.Client()})(context.Background(), io.Discard, nil)
				if err == nil {
					t.Fatal("expected read error")
				}
				fake.mu.Lock()
				defer fake.mu.Unlock()
				if len(fake.writes) != 0 {
					t.Fatalf("writes after failed read: %v", fake.writes)
				}
			})
		}
	}
}

func TestQuickstartPreservesUnrelatedSettings(t *testing.T) {
	for _, exists := range []bool{true, false} {
		t.Run(fmt.Sprintf("rule exists=%v", exists), func(t *testing.T) {
			current := losslessFixture(t)
			if !exists {
				current.Firewall.Rules = []config.Rule{}
			}
			fake := &configFake{reads: quickstartReads(current)}
			server := httptest.NewServer(http.HandlerFunc(fake.serve))
			defer server.Close()
			err := setOutboundQuickstartLANWAN(&API{BaseURL: server.URL, Client: server.Client()})(context.Background(), io.Discard, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := losslessFixture(t)
			want.Routing.Gateways[0].Address = "192.0.2.1"
			want.Routing.Gateways[0].Iface = "eth0"
			want.Routing.Gateways[0].Description = "Quick start: WAN default gateway"
			want.Routing.Routes[0].Iface = "eth0"
			want.Firewall.NAT.Enabled = true
			want.Firewall.NAT.EgressZone = "wan"
			want.Firewall.NAT.SourceZones = []string{"lan", "mgmt"}
			rulePath, method := "/api/v1/firewall/rules", http.MethodPost
			rule := config.Rule{ID: quickstartAllowRuleID}
			if exists {
				rulePath += "/" + quickstartAllowRuleID
				method = http.MethodPatch
				rule = current.Firewall.Rules[0]
			}
			rule.Description = "Quick start: allow LAN/MGMT to WAN"
			rule.SourceZones = []string{"lan", "mgmt"}
			rule.DestZones = []string{"wan"}
			rule.Action = config.ActionAllow
			wantWrites := []recordedWrite{
				{http.MethodPost, "/api/v1/routing", jsonValue(t, want.Routing)},
				{http.MethodPost, "/api/v1/firewall/nat", jsonValue(t, want.Firewall.NAT)},
				{method, rulePath, jsonValue(t, rule)},
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if !reflect.DeepEqual(fake.writes, wantWrites) {
				t.Fatalf("writes = %#v\nwant = %#v", fake.writes, wantWrites)
			}
		})
	}
}
