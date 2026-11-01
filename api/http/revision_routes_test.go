// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"strings"
)

var mutationRouteClass = map[string]string{
	"POST /api/v1/auth/login":                              "non-config",
	"POST /api/v1/auth/login/mfa":                          "non-config",
	"POST /api/v1/auth/logout":                             "non-config",
	"PATCH /api/v1/auth/me":                                "non-config",
	"POST /api/v1/auth/me/mfa/enroll":                      "non-config",
	"POST /api/v1/auth/me/mfa/enable":                      "non-config",
	"POST /api/v1/auth/me/mfa/disable":                     "non-config",
	"POST /api/v1/system/factory-reset":                    "config-writer",
	"POST /api/v1/config/validate":                         "non-config",
	"POST /api/v1/config":                                  "config-writer",
	"POST /api/v1/config/candidate":                        "config-writer",
	"POST /api/v1/config/commit":                           "config-writer",
	"POST /api/v1/config/import":                           "config-writer",
	"POST /api/v1/config/rollback":                         "config-writer",
	"POST /api/v1/users":                                   "non-config",
	"PATCH /api/v1/users/:id":                              "non-config",
	"DELETE /api/v1/users/:id":                             "non-config",
	"POST /api/v1/users/:id/mfa/disable":                   "non-config",
	"POST /api/v1/users/:id/mfa/require":                   "non-config",
	"POST /api/v1/users/:id/mfa/clear":                     "non-config",
	"POST /api/v1/users/:id/mfa/grace":                     "non-config",
	"POST /api/v1/services/syslog":                         "config-writer",
	"PATCH /api/v1/services/syslog":                        "config-writer",
	"POST /api/v1/services/dns":                            "config-writer",
	"POST /api/v1/services/ntp":                            "config-writer",
	"POST /api/v1/services/dhcp":                           "config-writer",
	"POST /api/v1/services/vpn":                            "config-writer",
	"POST /api/v1/firewall/rules":                          "config-writer",
	"POST /api/v1/firewall/rules/:id/move":                 "config-writer",
	"POST /api/v1/firewall/port-forwards":                  "config-writer",
	"DELETE /api/v1/firewall/port-forwards/:id":            "config-writer",
	"PATCH /api/v1/firewall/rules/:id":                     "config-writer",
	"DELETE /api/v1/firewall/rules/:id":                    "config-writer",
	"POST /api/v1/pcap/config":                             "config-writer",
	"POST /api/v1/pcap/start":                              "non-config",
	"POST /api/v1/pcap/stop":                               "non-config",
	"POST /api/v1/pcap/analyze":                            "non-config",
	"POST /api/v1/pcap/analyze/:name":                      "non-config",
	"POST /api/v1/templates/ics/apply":                     "config-writer",
	"POST /api/v1/firewall/rules/preview":                  "non-config",
	"POST /api/v1/learn/watches":                           "non-config",
	"POST /api/v1/learn/watches/:id/stop":                  "non-config",
	"DELETE /api/v1/learn/datasets/:id":                    "non-config",
	"POST /api/v1/learn/generate":                          "non-config",
	"POST /api/v1/learn/suggestions/:id/review":            "non-config",
	"POST /api/v1/learn/apply":                             "config-writer",
	"DELETE /api/v1/inventory":                             "non-config",
	"POST /api/v1/signatures":                              "non-config",
	"DELETE /api/v1/signatures/:id":                        "non-config",
	"DELETE /api/v1/anomalies":                             "non-config",
	"POST /api/v1/assets":                                  "config-writer",
	"PATCH /api/v1/assets/:id":                             "config-writer",
	"DELETE /api/v1/assets/:id":                            "config-writer",
	"POST /api/v1/objects":                                 "config-writer",
	"PATCH /api/v1/objects/:id":                            "config-writer",
	"DELETE /api/v1/objects/:id":                           "config-writer",
	"POST /api/v1/zones":                                   "config-writer",
	"PATCH /api/v1/zones/:name":                            "config-writer",
	"DELETE /api/v1/zones/:name":                           "config-writer",
	"POST /api/v1/interfaces":                              "config-writer",
	"PATCH /api/v1/interfaces/:name":                       "config-writer",
	"DELETE /api/v1/interfaces/:name":                      "config-writer",
	"POST /api/v1/dataplane":                               "config-writer",
	"POST /api/v1/routing":                                 "config-writer",
	"POST /api/v1/firewall/nat":                            "config-writer",
	"POST /api/v1/ids/rules":                               "config-writer",
	"POST /api/v1/services/av":                             "config-writer",
	"POST /api/v1/services/proxy/forward":                  "config-writer",
	"POST /api/v1/services/proxy/reverse":                  "config-writer",
	"POST /api/v1/interfaces/assign":                       "config-writer",
	"POST /api/v1/interfaces/reconcile":                    "non-config",
	"POST /api/v1/routing/reconcile":                       "non-config",
	"POST /api/v1/auth/me/password":                        "non-config",
	"POST /api/v1/users/:id/password":                      "non-config",
	"POST /api/v1/config/backups":                          "non-config",
	"DELETE /api/v1/config/backups/:id":                    "non-config",
	"POST /api/v1/config/commit_confirmed":                 "config-writer",
	"POST /api/v1/config/confirm":                          "config-writer",
	"POST /api/v1/simulation":                              "non-config",
	"POST /api/v1/conntrack/kill":                          "non-config",
	"POST /api/v1/dataplane/blocks/host":                   "non-config",
	"POST /api/v1/dataplane/blocks/flow":                   "non-config",
	"POST /api/v1/system/tls/cert":                         "non-config",
	"POST /api/v1/system/tls/trusted-ca":                   "non-config",
	"POST /api/v1/ids/convert/sigma":                       "non-config",
	"POST /api/v1/ids/import":                              "config-writer",
	"POST /api/v1/ids/restore":                             "config-writer",
	"POST /api/v1/pcap/upload":                             "non-config",
	"DELETE /api/v1/pcap/:name":                            "non-config",
	"POST /api/v1/pcap/tag":                                "non-config",
	"POST /api/v1/pcap/replay":                             "non-config",
	"POST /api/v1/templates/apply":                         "config-writer",
	"POST /api/v1/firewall/ics-rules":                      "config-writer",
	"PATCH /api/v1/firewall/ics-rules/:id":                 "config-writer",
	"POST /api/v1/identities":                              "config-writer",
	"DELETE /api/v1/identities/:ip":                        "config-writer",
	"POST /api/v1/cli/execute":                             "cli-transport",
	"POST /api/v1/cli/ws/ticket":                           "non-config",
	"POST /api/v1/services/vpn/openvpn/profile":            "config-writer",
	"POST /api/v1/services/vpn/openvpn/clients":            "non-config",
	"POST /api/v1/services/vpn/openvpn/clients/:id/revoke": "non-config",
	"POST /api/v1/services/av/update":                      "non-config",
	"POST /api/v1/services/av/defs":                        "non-config",
	"DELETE /api/v1/services/av/defs":                      "non-config",
}

func isConfigWriterRequest(request *http.Request) bool { return configWriterRoute(request) != "" }

func configWriterRoute(request *http.Request) string {
	for key, class := range mutationRouteClass {
		if class != "config-writer" {
			continue
		}
		method, route, _ := strings.Cut(key, " ")
		if request.Method != method {
			continue
		}
		want, got := strings.Split(route, "/"), strings.Split(request.URL.Path, "/")
		if len(want) != len(got) {
			continue
		}
		match := true
		for i := range want {
			if !strings.HasPrefix(want[i], ":") && want[i] != got[i] {
				match = false
				break
			}
		}
		if match {
			return key
		}
	}
	return ""
}
