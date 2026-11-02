// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

func registerVPNServiceCommands(r *Registry, api *API) {
	const vpn = "/api/v1/services/vpn"
	r.RegisterRole("set vpn openvpn source", RoleAdmin, setServiceOpenVPNSource(api))
	registerServiceFields(r, api, "vpn wireguard", vpn, []serviceField{
		{"enabled", "wireguard.enabled", serviceBool}, {"interface", "wireguard.interface", serviceText},
		{"listen-port", "wireguard.listenPort", serviceInt(0, 65535)}, {"listen-zone", "wireguard.listenZone", serviceText},
		{"listen-interfaces", "wireguard.listenInterfaces", serviceList}, {"address-cidr", "wireguard.addressCIDR", serviceText},
		{"private-key-file", "wireguard.privateKey", serviceSecretFile},
	})
	registerServiceCollection(r, api, serviceCollection{
		name: "vpn wireguard peer", endpoint: vpn, path: "wireguard.peers", keys: []string{"publicKey"},
		fields: []serviceField{
			{"name", "name", serviceText}, {"allowed-ips", "allowedIPs", serviceList}, {"endpoint", "endpoint", serviceText},
			{"persistent-keepalive", "persistentKeepalive", serviceInt(0, 65535)},
		}, required: []string{"allowed-ips"},
	})
	registerServiceFields(r, api, "vpn openvpn", vpn, []serviceField{
		{"enabled", "openvpn.enabled", serviceBool}, {"mode", "openvpn.mode", serviceEnum("server", "client")},
		{"config-path", "openvpn.configPath", serviceText},
	})
	registerServiceFields(r, api, "vpn openvpn client", vpn, []serviceField{
		{"remote", "openvpn.managed.remote", serviceText}, {"port", "openvpn.managed.port", serviceInt(0, 65535)},
		{"proto", "openvpn.managed.proto", serviceEnum("udp", "tcp")}, {"username", "openvpn.managed.username", serviceText},
		{"password-file", "openvpn.managed.password", serviceSecretFile}, {"ca-file", "openvpn.managed.ca", serviceSecretFile},
		{"cert-file", "openvpn.managed.cert", serviceSecretFile}, {"key-file", "openvpn.managed.key", serviceSecretFile},
	})
	registerServiceFields(r, api, "vpn openvpn server", vpn, []serviceField{
		{"listen-port", "openvpn.server.listenPort", serviceInt(0, 65535)}, {"proto", "openvpn.server.proto", serviceEnum("udp", "tcp")},
		{"listen-zone", "openvpn.server.listenZone", serviceText}, {"listen-interfaces", "openvpn.server.listenInterfaces", serviceList},
		{"tunnel-cidr", "openvpn.server.tunnelCIDR", serviceText}, {"public-endpoint", "openvpn.server.publicEndpoint", serviceText},
		{"push-dns", "openvpn.server.pushDNS", serviceList}, {"push-routes", "openvpn.server.pushRoutes", serviceList},
		{"client-to-client", "openvpn.server.clientToClient", serviceBool},
	})
}

// Changing source is explicit because OpenVPN validates server and client
// configuration independently; keeping the inactive source would block a switch.
func setServiceOpenVPNSource(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: set vpn openvpn source <profile|client|server>")
		}
		if _, err := serviceEnum("profile", "client", "server")(args[0]); err != nil {
			return err
		}
		return editService(api, "/api/v1/services/vpn", func(o serviceObject) error {
			var ovpn serviceObject
			if raw, ok := o["openvpn"]; ok {
				if err := json.Unmarshal(raw, &ovpn); err != nil {
					return err
				}
			}
			if ovpn == nil {
				ovpn = serviceObject{}
			}
			switch args[0] {
			case "profile":
				delete(ovpn, "managed")
				delete(ovpn, "server")
			case "client":
				delete(ovpn, "server")
				delete(ovpn, "configPath")
			case "server":
				delete(ovpn, "managed")
				delete(ovpn, "configPath")
			}
			if args[0] != "profile" {
				if err := ovpn.put("mode", args[0]); err != nil {
					return err
				}
			}
			return o.put("openvpn", ovpn)
		})(ctx, out, nil)
	}
}
