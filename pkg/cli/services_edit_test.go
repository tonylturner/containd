// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Synchronous transport: no listener, worker, timer or runtime service required.
type serviceEditClient struct {
	t                               *testing.T
	endpoint, initial, readRevision string
	readStatus, writeStatus         int
	payload                         serviceObject
	requests                        []string
}

func (f *serviceEditClient) Do(req *http.Request) (*http.Response, error) {
	f.t.Helper()
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}
	f.requests = append(f.requests, req.Method+" "+req.URL.Path)
	if req.URL.Path != f.endpoint {
		f.t.Fatalf("unexpected path %s", req.URL.Path)
	}
	if req.Header.Get("Authorization") != "Bearer service-token" {
		f.t.Fatal("missing authentication")
	}
	if req.Method == http.MethodGet {
		status := f.readStatus
		if status == 0 {
			status = 200
		}
		return &http.Response{StatusCode: status, Header: http.Header{"X-Containd-Revision": []string{f.readRevision}}, Body: io.NopCloser(strings.NewReader(f.initial))}, nil
	}
	if req.Method != http.MethodPost {
		f.t.Fatalf("unexpected method: %s", req.Method)
	}
	if req.Header.Get("X-Containd-If-Revision") != f.readRevision {
		f.t.Fatal("write not bound to read revision")
	}
	if req.Header.Get("Content-Type") != "application/json" {
		f.t.Fatal("missing content type")
	}
	if err := json.Unmarshal(body, &f.payload); err != nil {
		f.t.Fatal(err)
	}
	if f.writeStatus != 0 {
		return jsonHTTPResponse(f.writeStatus, map[string]string{"error": "rejected", "code": "config_revision_mismatch", "currentRevision": "0123456789abcdef.8"}, nil), nil
	}
	return jsonHTTPResponse(200, map[string]string{"secret": "MUST-NOT-PRINT"}, map[string]string{
		"X-Containd-Revision": "0123456789abcdef.8", "X-Containd-Config": "staged",
	}), nil
}
func newServiceEditClient(t *testing.T, endpoint, initial string) *serviceEditClient {
	return &serviceEditClient{t: t, endpoint: endpoint, initial: initial, readRevision: "0123456789abcdef.7"}
}
func serviceRegistry(client HTTPClient) *Registry {
	return NewRegistry(nil, &API{BaseURL: "http://test", Token: "service-token", Client: client})
}
func serviceJSON(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

type serviceEditCase struct{ line, initial, want string }

func runServiceEdits(t *testing.T, endpoint string, cases []serviceEditCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			client := newServiceEditClient(t, endpoint, tc.initial)
			var out bytes.Buffer
			err := serviceRegistry(client).ParseAndExecute(WithRole(context.Background(), "admin"), tc.line, &out)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(client.payload)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(serviceJSON(t, raw), serviceJSON(t, []byte(tc.want))) {
				t.Fatalf("payload=%s; want=%s", raw, tc.want)
			}
			if !reflect.DeepEqual(client.requests, []string{"GET " + endpoint, "POST " + endpoint}) {
				t.Fatalf("requests=%v", client.requests)
			}
			if out.String() != stagedMessage+"\n" {
				t.Fatalf("output=%q", out.String())
			}
		})
	}
}
func TestServiceDNSFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/dns", []serviceEditCase{
		{`set dns enabled on`, `{"enabled":false,"listenPort":5353,"upstreamServers":["1.1.1.1"]}`, `{"enabled":true,"listenPort":5353,"upstreamServers":["1.1.1.1"]}`},
		{`set dns upstream-servers 1.1.1.1,9.9.9.9`, `{"enabled":false,"listenZones":["lan"]}`, `{"enabled":false,"listenZones":["lan"],"upstreamServers":["1.1.1.1","9.9.9.9"]}`},
		{`set dns listen-zones -`, `{"enabled":true,"listenZones":["lan"]}`, `{"enabled":true,"listenZones":[]}`},
		{`set dns listen-port 0`, `{"enabled":false}`, `{"enabled":false,"listenPort":0}`},
		{`set dns cache-size-mb 64`, `{"enabled":false}`, `{"enabled":false,"cacheSizeMB":64}`},
	})
}
func TestServiceNTPFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/ntp", []serviceEditCase{
		{`set ntp enabled false`, `{"enabled":true,"servers":["pool.ntp.org"],"intervalSeconds":64}`, `{"enabled":false,"servers":["pool.ntp.org"],"intervalSeconds":64}`},
		{`set ntp servers time.example.com,time2.example.com`, `{"enabled":true}`, `{"enabled":true,"servers":["time.example.com","time2.example.com"]}`},
		{`set ntp interval-seconds 0`, `{"enabled":false,"servers":["pool.ntp.org"]}`, `{"enabled":false,"servers":["pool.ntp.org"],"intervalSeconds":0}`},
	})
}
func TestServiceDHCPFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/dhcp", []serviceEditCase{
		{`set dhcp enabled on`, `{"enabled":false,"authoritative":true,"pools":[]}`, `{"enabled":true,"authoritative":true,"pools":[]}`},
		{`set dhcp authoritative false`, `{"enabled":true,"authoritative":true}`, `{"enabled":true,"authoritative":false}`},
		{`set dhcp listen-ifaces lan,dmz`, `{"enabled":false}`, `{"enabled":false,"listenIfaces":["lan","dmz"]}`},
		{`set dhcp lease-seconds 3600`, `{"enabled":false}`, `{"enabled":false,"leaseSeconds":3600}`},
		{`set dhcp router 10.0.0.1`, `{"enabled":false}`, `{"enabled":false,"router":"10.0.0.1"}`},
		{`set dhcp dns-servers 10.0.0.1`, `{"enabled":false}`, `{"enabled":false,"dnsServers":["10.0.0.1"]}`},
		{`set dhcp domain plant.example`, `{"enabled":false}`, `{"enabled":false,"domain":"plant.example"}`},
		{`add dhcp pool lan 10.0.0.30 --end 10.0.0.40`, `{"pools":[{"iface":"lan","start":"10.0.0.10","end":"10.0.0.20"}]}`, `{"pools":[{"iface":"lan","start":"10.0.0.10","end":"10.0.0.20"},{"iface":"lan","start":"10.0.0.30","end":"10.0.0.40"}]}`},
		{`set dhcp pool lan 10.0.0.10 --end 10.0.0.25`, `{"pools":[{"iface":"lan","start":"10.0.0.10","end":"10.0.0.20"}]}`, `{"pools":[{"iface":"lan","start":"10.0.0.10","end":"10.0.0.25"}]}`},
		{`delete dhcp pool lan 10.0.0.10`, `{"pools":[{"iface":"lan","start":"10.0.0.10","end":"10.0.0.20"}],"reservations":[]}`, `{"pools":[],"reservations":[]}`},
		{`add dhcp reservation lan AA:BB:CC:DD:EE:FF --ip 10.0.0.12`, `{"pools":[]}`, `{"pools":[],"reservations":[{"iface":"lan","mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.12"}]}`},
		{`set dhcp reservation lan aa:bb:cc:dd:ee:ff --ip 10.0.0.13`, `{"reservations":[{"iface":"lan","mac":"AA:BB:CC:DD:EE:FF","ip":"10.0.0.12"}]}`, `{"reservations":[{"iface":"lan","mac":"AA:BB:CC:DD:EE:FF","ip":"10.0.0.13"}]}`},
		{`delete dhcp reservation lan AA:BB:CC:DD:EE:FF`, `{"reservations":[{"iface":"lan","mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.12"}]}`, `{"reservations":[]}`},
	})
}
func TestServiceSyslogFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/syslog", []serviceEditCase{
		{`set syslog batch-size 0`, `{"format":"json","forwarders":[{"address":"10.0.0.5","port":514,"proto":"tcp"}],"flushEvery":10}`, `{"format":"json","forwarders":[{"address":"10.0.0.5","port":514,"proto":"tcp"}],"flushEvery":10,"batchSize":0}`},
		{`set syslog flush-every 2`, `{"format":"json","batchSize":100}`, `{"format":"json","batchSize":100,"flushEvery":2}`},
	})
}
func TestServiceProxyFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/proxy/forward", []serviceEditCase{
		{`set proxy forward allowed-domains example.com,example.org`, `{"enabled":true,"listenPort":3128,"listenZones":["lan"]}`, `{"enabled":true,"listenPort":3128,"listenZones":["lan"],"allowedDomains":["example.com","example.org"]}`},
		{`set proxy forward log-requests false`, `{"enabled":true,"logRequests":true}`, `{"enabled":true,"logRequests":false}`},
		{`set proxy forward allowed-clients -`, `{"enabled":false,"allowedClients":["legacy"]}`, `{"enabled":false,"allowedClients":[]}`},
		{`set proxy forward upstream ''`, `{"enabled":false,"upstream":"http://old:3128"}`, `{"enabled":false,"upstream":""}`},
	})
	runServiceEdits(t, "/api/v1/services/proxy/reverse", []serviceEditCase{
		{`add proxy reverse site plant --listen-port 443 --backends 10.0.0.10:8080 --hostnames plant.example --tls-enabled true --cert-ref plant --description 'Plant portal'`, `{"enabled":false}`, `{"enabled":false,"sites":[{"name":"plant","listenPort":443,"backends":["10.0.0.10:8080"],"hostnames":["plant.example"],"tlsEnabled":true,"certRef":"plant","description":"Plant portal"}]}`},
		{`set proxy reverse site plant --tls-enabled false --cert-ref ''`, `{"enabled":true,"sites":[{"name":"plant","tlsEnabled":true,"certRef":"plant","backends":["10.0.0.10:8080"],"listenPort":443}]}`, `{"enabled":true,"sites":[{"name":"plant","tlsEnabled":false,"certRef":"","backends":["10.0.0.10:8080"],"listenPort":443}]}`},
		{`delete proxy reverse site plant`, `{"enabled":true,"sites":[{"name":"plant"},{"name":"other"}]}`, `{"enabled":true,"sites":[{"name":"other"}]}`},
	})
}
func TestServiceAVFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/av", []serviceEditCase{
		{`set av enabled false`, `{"enabled":true,"httpDownload":true,"scan":{"include":[{"destPorts":["80"]}]}}`, `{"enabled":false,"httpDownload":true,"scan":{"include":[{"destPorts":["80"]}]}}`},
		{`set av mode icap`, `{"enabled":false,"mode":"clamav"}`, `{"enabled":false,"mode":"icap"}`},
		{`set av fail-policy closed`, `{"enabled":false}`, `{"enabled":false,"failPolicy":"closed"}`},
		{`set av max-size-bytes 104857600`, `{"enabled":false,"cacheTtl":9007199254740993}`, `{"enabled":false,"cacheTtl":9007199254740993,"maxSizeBytes":104857600}`},
		{`set av timeout-sec 60`, `{"enabled":false}`, `{"enabled":false,"timeoutSec":60}`},
		{`set av cache-ttl 5m`, `{"mode":"icap","httpUpload":true}`, `{"mode":"icap","httpUpload":true,"cacheTtl":300000000000}`},
		{`set av cache-ttl 0s`, `{"cacheTtl":123}`, `{"cacheTtl":0}`},
		{`set av http-download true`, `{"httpUpload":false}`, `{"httpUpload":false,"httpDownload":true}`},
		{`set av http-upload true`, `{"httpDownload":false}`, `{"httpDownload":false,"httpUpload":true}`},
		{`set av clamav freshclam-enabled false`, `{"clamav":{"socketPath":"/run/clamd.sock","freshclamEnabled":true}}`, `{"clamav":{"socketPath":"/run/clamd.sock","freshclamEnabled":false}}`},
		{`set av clamav update-schedule 4h`, `{"clamav":{"customDefsPath":"/data/defs"}}`, `{"clamav":{"customDefsPath":"/data/defs","updateSchedule":"4h"}}`},
		{`set av icap server scanner:1344 true avscan`, `{"icap":{"servers":[{"address":"old:1344"}]},"mode":"icap"}`, `{"icap":{"servers":[{"address":"scanner:1344","useTls":true,"service":"avscan"}]},"mode":"icap"}`},
		{`set av scan download-mode stream_tail`, `{"scan":{"icsZones":["plant"]}}`, `{"scan":{"icsZones":["plant"],"downloadMode":"stream_tail"}}`},
		{`set av scan ics-assets pump`, `{"scan":{"icsZones":["plant"]}}`, `{"scan":{"icsZones":["plant"],"icsAssets":["pump"]}}`},
		{`set av scan ics-zones -`, `{"scan":{"icsZones":["plant"]}}`, `{"scan":{"icsZones":[]}}`},
		{`add av scan include --source-zones lan --dest-zones wan --dest-ports 80,8080-8090`, `{"scan":{"exclude":[{"sources":["10.0.0.5/32"]}]}}`, `{"scan":{"exclude":[{"sources":["10.0.0.5/32"]}],"include":[{"sourceZones":["lan"],"destZones":["wan"],"destPorts":["80","8080-8090"]}]}}`},
		{`set av scan include 1 --dest-ports 8080`, `{"scan":{"include":[{"destPorts":["80"],"sourceZones":["lan"]}]}}`, `{"scan":{"include":[{"destPorts":["8080"],"sourceZones":["lan"]}]}}`},
		{`delete av scan include 1`, `{"scan":{"include":[{"destPorts":["80"]}]}}`, `{"scan":{"include":[]}}`},
		{`add av scan exclude --sources 10.0.0.0/24 --destinations 192.0.2.0/24`, `{}`, `{"scan":{"exclude":[{"sources":["10.0.0.0/24"],"destinations":["192.0.2.0/24"]}]}}`},
		{`set av scan exclude 1 --source-zones plant --dest-ports 80`, `{"scan":{"exclude":[{"sources":["10.0.0.5/32"]}]}}`, `{"scan":{"exclude":[{"sources":["10.0.0.5/32"],"sourceZones":["plant"],"destPorts":["80"]}]}}`},
		{`delete av scan exclude 1`, `{"scan":{"exclude":[{"sources":["10.0.0.5/32"]}]}}`, `{"scan":{"exclude":[]}}`},
	})
}
func TestServiceVPNFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/services/vpn", []serviceEditCase{
		{`set vpn wireguard enabled on`, `{"wireguard":{"enabled":false,"peers":[{"publicKey":"peer"}]},"openvpn":{"enabled":true}}`, `{"wireguard":{"enabled":true,"peers":[{"publicKey":"peer"}]},"openvpn":{"enabled":true}}`},
		{`set vpn wireguard address-cidr 10.8.0.1/24`, `{"wireguard":{"listenPort":51820}}`, `{"wireguard":{"listenPort":51820,"addressCIDR":"10.8.0.1/24"}}`},
		{`set vpn wireguard listen-interfaces eth1,eth2`, `{"wireguard":{"listenZone":"wan"}}`, `{"wireguard":{"listenZone":"wan","listenInterfaces":["eth1","eth2"]}}`},
		{`add vpn wireguard peer peer-key --allowed-ips 10.8.0.2/32 --name laptop --endpoint vpn.example:51820 --persistent-keepalive 25`, `{"wireguard":{"enabled":false},"openvpn":{"mode":"server"}}`, `{"wireguard":{"enabled":false,"peers":[{"publicKey":"peer-key","allowedIPs":["10.8.0.2/32"],"name":"laptop","endpoint":"vpn.example:51820","persistentKeepalive":25}]},"openvpn":{"mode":"server"}}`},
		{`set vpn wireguard peer peer-key --persistent-keepalive 0`, `{"wireguard":{"peers":[{"publicKey":"peer-key","allowedIPs":["10.8.0.2/32"],"persistentKeepalive":25}]}}`, `{"wireguard":{"peers":[{"publicKey":"peer-key","allowedIPs":["10.8.0.2/32"],"persistentKeepalive":0}]}}`},
		{`delete vpn wireguard peer peer-key`, `{"wireguard":{"peers":[{"publicKey":"peer-key"}]}}`, `{"wireguard":{"peers":[]}}`},
		{`set vpn openvpn enabled false`, `{"openvpn":{"enabled":true,"mode":"server","server":{"tunnelCIDR":"10.9.0.0/24"}}}`, `{"openvpn":{"enabled":false,"mode":"server","server":{"tunnelCIDR":"10.9.0.0/24"}}}`},
		{`set vpn openvpn source client`, `{"wireguard":{"enabled":true},"openvpn":{"enabled":false,"server":{"tunnelCIDR":"10.9.0.0/24"},"configPath":"/old.ovpn"}}`, `{"wireguard":{"enabled":true},"openvpn":{"enabled":false,"mode":"client"}}`},
		{`set vpn openvpn source server`, `{"openvpn":{"enabled":false,"managed":{"remote":"old"},"configPath":"/old.ovpn","server":{"listenPort":1194}}}`, `{"openvpn":{"enabled":false,"mode":"server","server":{"listenPort":1194}}}`},
		{`set vpn openvpn source profile`, `{"openvpn":{"enabled":false,"managed":{"remote":"old"},"configPath":"/new.ovpn"}}`, `{"openvpn":{"enabled":false,"configPath":"/new.ovpn"}}`},
		{`set vpn openvpn client remote vpn.example.com`, `{"openvpn":{"managed":{"username":"operator"}}}`, `{"openvpn":{"managed":{"username":"operator","remote":"vpn.example.com"}}}`},
		{`set vpn openvpn client proto tcp`, `{"openvpn":{"managed":{"remote":"vpn.example.com","port":1194}}}`, `{"openvpn":{"managed":{"remote":"vpn.example.com","port":1194,"proto":"tcp"}}}`},
		{`set vpn openvpn server tunnel-cidr 10.9.0.0/24`, `{"openvpn":{"mode":"server"}}`, `{"openvpn":{"mode":"server","server":{"tunnelCIDR":"10.9.0.0/24"}}}`},
		{`set vpn openvpn server push-routes 10.0.0.0/8,192.168.0.0/16`, `{"openvpn":{"server":{"listenPort":1194}}}`, `{"openvpn":{"server":{"listenPort":1194,"pushRoutes":["10.0.0.0/8","192.168.0.0/16"]}}}`},
	})
}
func TestServiceVPNCredentialFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("SECRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ command, want string }{
		{"set vpn wireguard private-key-file", `{"wireguard":{"privateKey":"SECRET"}}`},
		{"set vpn openvpn client password-file", `{"openvpn":{"managed":{"password":"SECRET"}}}`},
		{"set vpn openvpn client ca-file", `{"openvpn":{"managed":{"ca":"SECRET"}}}`},
		{"set vpn openvpn client cert-file", `{"openvpn":{"managed":{"cert":"SECRET"}}}`},
		{"set vpn openvpn client key-file", `{"openvpn":{"managed":{"key":"SECRET"}}}`},
	} {
		runServiceEdits(t, "/api/v1/services/vpn", []serviceEditCase{{tc.command + " '" + path + "'", `{}`, tc.want}})
	}
}

func TestServiceVPNRejectsEmptyCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-credential")
	if err := os.WriteFile(path, []byte("\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client := newServiceEditClient(t, "", `{}`)
	err := serviceRegistry(client).Execute(WithRole(context.Background(), "admin"),
		"set vpn wireguard private-key-file", io.Discard, []string{path})
	if err == nil || !strings.Contains(err.Error(), "credential file is empty") || len(client.requests) != 0 {
		t.Fatalf("empty credential reached API: %v %v", err, client.requests)
	}
}

func TestServiceIDSFocusedEdits(t *testing.T) {
	runServiceEdits(t, "/api/v1/ids/rules", []serviceEditCase{
		{`set ids enabled false`, `{"enabled":true,"rules":[{"id":"r","rawSource":"alert tcp any any -> any any (sid:1;)","labels":{"owner":"plant"},"when":{"field":"proto","value":"modbus"}}],"ruleGroups":[{"id":"g","enabled":true}]}`, `{"enabled":false,"rules":[{"id":"r","rawSource":"alert tcp any any -> any any (sid:1;)","labels":{"owner":"plant"},"when":{"field":"proto","value":"modbus"}}],"ruleGroups":[{"id":"g","enabled":true}]}`},
		{`set ids rule enabled r false`, `{"enabled":true,"rules":[{"id":"r","when":{"field":"port","value":502}},{"id":"other","enabled":true}],"ruleGroups":[]}`, `{"enabled":true,"rules":[{"id":"r","enabled":false,"when":{"field":"port","value":502}},{"id":"other","enabled":true}],"ruleGroups":[]}`},
		{`add ids group plant --name 'Plant rules' --description 'Plant monitoring' --filter 'proto:modbus'`, `{"enabled":true,"rules":[{"id":"r"}]}`, `{"enabled":true,"rules":[{"id":"r"}],"ruleGroups":[{"id":"plant","name":"Plant rules","description":"Plant monitoring","filter":"proto:modbus","enabled":true}]}`},
		{`set ids group plant --enabled false --filter 'sourceFormat:suricata AND proto:modbus'`, `{"ruleGroups":[{"id":"plant","name":"Plant rules","enabled":true}]}`, `{"ruleGroups":[{"id":"plant","name":"Plant rules","enabled":false,"filter":"sourceFormat:suricata AND proto:modbus"}]}`},
		{`delete ids group plant`, `{"enabled":true,"ruleGroups":[{"id":"plant","name":"Plant rules"}],"rules":[{"id":"r"}]}`, `{"enabled":true,"ruleGroups":[],"rules":[{"id":"r"}]}`},
	})
}

func TestServiceEditsRefuseFailedReadAndStaleWrite(t *testing.T) {
	for _, tc := range []struct{ line, endpoint string }{
		{"set dns enabled true", "/api/v1/services/dns"}, {"set ntp enabled true", "/api/v1/services/ntp"},
		{"set dhcp enabled true", "/api/v1/services/dhcp"}, {"set av enabled true", "/api/v1/services/av"},
		{"set vpn wireguard enabled true", "/api/v1/services/vpn"}, {"set proxy forward log-requests true", "/api/v1/services/proxy/forward"},
		{"set ids enabled true", "/api/v1/ids/rules"}, {"set syslog batch-size 10", "/api/v1/services/syslog"},
	} {
		for _, kind := range []string{"null", "missing revision", "read failure", "malformed", "conflict", "validation"} {
			t.Run(tc.line+"/"+kind, func(t *testing.T) {
				client := newServiceEditClient(t, tc.endpoint, `{}`)
				switch kind {
				case "null":
					client.initial = "null"
				case "missing revision":
					client.readRevision = ""
				case "read failure":
					client.readStatus = 503
				case "malformed":
					client.initial = "[1,2]"
				case "conflict":
					client.writeStatus = 412
				case "validation":
					client.writeStatus = 400
				}
				var out bytes.Buffer
				err := serviceRegistry(client).ParseAndExecute(WithRole(context.Background(), "admin"), tc.line, &out)
				if err == nil || out.Len() != 0 {
					t.Fatalf("err=%v output=%q", err, out.String())
				}
				wantRequests := 1
				if kind == "conflict" || kind == "validation" {
					wantRequests = 2
				}
				if len(client.requests) != wantRequests {
					t.Fatalf("unexpected retry/write: %v", client.requests)
				}
				if kind == "conflict" {
					var failure *ConfigFailure
					if !errors.As(err, &failure) || failure.Status != 412 {
						t.Fatalf("lost conflict detail: %v", err)
					}
				}
			})
		}
	}
}
func TestServiceEditsRejectInvalidIntent(t *testing.T) {
	for _, line := range []string{
		"set dns enabled maybe", "set dns enabled true extra", "set dns listen-port 65536", "set dns upstream-servers 1.1.1.1,,9.9.9.9",
		"set av cache-ttl -1s", "set av cache-ttl 9223372036854775807h", "set av cache-ttl 300", "set av fail-policy maybe",
		"set av max-size-bytes -1", "set av scan download-mode maybe", "set vpn openvpn mode maybe", "set syslog batch-size -1",
		"add dhcp pool lan 10.0.0.1", "add dhcp reservation lan invalid --ip 10.0.0.1", "set proxy reverse site x --listen-port 0",
		"set ids rule enabled r", "set ids group g --rule-count 1", "set av backend-disabled true",
		"set vpn wireguard private-key-file /no/such/credential", "add vpn wireguard peer key --allowed-ips 10.0.0.1/32 --name x --name y",
	} {
		t.Run(line, func(t *testing.T) {
			client := newServiceEditClient(t, "", `{}`)
			err := serviceRegistry(client).ParseAndExecute(WithRole(context.Background(), "admin"), line, io.Discard)
			if err == nil || len(client.requests) != 0 {
				t.Fatalf("invalid intent reached API: %v %v", err, client.requests)
			}
		})
	}
}
func TestServiceCollectionRejectsMissingDuplicateAndAmbiguousKeys(t *testing.T) {
	for _, tc := range []serviceEditCase{
		{line: `set dhcp pool lan 10.0.0.1 --end 10.0.0.9`, initial: `{"pools":[]}`},
		{line: `delete proxy reverse site missing`, initial: `{"sites":[]}`},
		{line: `set ids rule enabled missing false`, initial: `{"rules":[]}`},
		{line: `set av scan include 0 --dest-ports 80`, initial: `{"scan":{"include":[{"destPorts":["80"]}]}}`},
		{line: `add ids group g --name duplicate`, initial: `{"ruleGroups":[{"id":"g"}]}`},
		{line: `set vpn wireguard peer k --name changed`, initial: `{"wireguard":{"peers":[{"publicKey":"k"},{"publicKey":"k"}]}}`},
		{line: `delete dhcp reservation lan aa:bb:cc:dd:ee:ff`, initial: `{"reservations":[null]}`},
	} {
		t.Run(tc.line, func(t *testing.T) {
			// The path is irrelevant to this test; bind to the handler's first read.
			endpoint := "/api/v1/services/dhcp"
			switch {
			case strings.Contains(tc.line, "proxy"):
				endpoint = "/api/v1/services/proxy/reverse"
			case strings.Contains(tc.line, "ids"):
				endpoint = "/api/v1/ids/rules"
			case strings.Contains(tc.line, "av scan"):
				endpoint = "/api/v1/services/av"
			case strings.Contains(tc.line, "vpn"):
				endpoint = "/api/v1/services/vpn"
			}
			client := newServiceEditClient(t, endpoint, tc.initial)
			err := serviceRegistry(client).ParseAndExecute(WithRole(context.Background(), "admin"), tc.line, io.Discard)
			if err == nil || len(client.requests) != 1 {
				t.Fatalf("unsafe collection write: %v %v", err, client.requests)
			}
		})
	}
}
func TestServiceSettersAreAdminOnly(t *testing.T) {
	r := &Registry{}
	api := &API{}
	registerNetworkServiceCommands(r, api)
	registerAVServiceCommands(r, api)
	registerVPNServiceCommands(r, api)
	registerProxyServiceCommands(r, api)
	registerIDSServiceCommands(r, api)
	for _, name := range r.Commands() {
		if r.roles[name] != RoleAdmin {
			t.Fatalf("%s not admin-only", name)
		}
		err := r.Execute(WithRole(context.Background(), "view"), name, io.Discard, nil)
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s allowed viewer: %v", name, err)
		}
	}
}
