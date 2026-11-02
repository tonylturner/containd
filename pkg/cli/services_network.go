// SPDX-License-Identifier: Apache-2.0
package cli

func registerNetworkServiceCommands(r *Registry, api *API) {
	registerServiceFields(r, api, "dns", "/api/v1/services/dns", []serviceField{
		{"enabled", "enabled", serviceBool}, {"listen-port", "listenPort", serviceInt(0, 65535)},
		{"listen-zones", "listenZones", serviceList}, {"upstream-servers", "upstreamServers", serviceList},
		{"cache-size-mb", "cacheSizeMB", serviceInt(0, 1<<31-1)},
	})
	registerServiceFields(r, api, "ntp", "/api/v1/services/ntp", []serviceField{
		{"enabled", "enabled", serviceBool}, {"servers", "servers", serviceList},
		{"interval-seconds", "intervalSeconds", serviceInt(0, 1<<31-1)},
	})
	const dhcp = "/api/v1/services/dhcp"
	registerServiceFields(r, api, "dhcp", dhcp, []serviceField{
		{"enabled", "enabled", serviceBool}, {"authoritative", "authoritative", serviceBool},
		{"listen-ifaces", "listenIfaces", serviceList}, {"lease-seconds", "leaseSeconds", serviceInt(0, 1<<31-1)},
		{"router", "router", serviceText}, {"dns-servers", "dnsServers", serviceList}, {"domain", "domain", serviceText},
	})
	registerServiceCollection(r, api, serviceCollection{
		name: "dhcp pool", endpoint: dhcp, path: "pools", keys: []string{"iface", "start"},
		fields: []serviceField{{"end", "end", serviceText}}, required: []string{"end"},
	})
	registerServiceCollection(r, api, serviceCollection{
		name: "dhcp reservation", endpoint: dhcp, path: "reservations", keys: []string{"iface", "mac"},
		fields: []serviceField{{"ip", "ip", serviceText}}, required: []string{"ip"},
	})
	registerServiceFields(r, api, "syslog", "/api/v1/services/syslog", []serviceField{
		{"batch-size", "batchSize", serviceInt(0, 1<<31-1)}, {"flush-every", "flushEvery", serviceInt(0, 1<<31-1)},
	})
}
