// SPDX-License-Identifier: Apache-2.0
package cli

func registerProxyServiceCommands(r *Registry, api *API) {
	registerServiceFields(r, api, "proxy forward", "/api/v1/services/proxy/forward", []serviceField{
		{"allowed-clients", "allowedClients", serviceList}, {"allowed-domains", "allowedDomains", serviceList},
		{"upstream", "upstream", serviceText}, {"log-requests", "logRequests", serviceBool},
	})
	registerServiceCollection(r, api, serviceCollection{
		name: "proxy reverse site", endpoint: "/api/v1/services/proxy/reverse", path: "sites", keys: []string{"name"},
		fields: []serviceField{
			{"listen-port", "listenPort", serviceInt(1, 65535)}, {"hostnames", "hostnames", serviceList},
			{"backends", "backends", serviceList}, {"tls-enabled", "tlsEnabled", serviceBool},
			{"cert-ref", "certRef", serviceText}, {"description", "description", serviceText},
		}, required: []string{"listen-port", "backends"},
	})
}
