// SPDX-License-Identifier: Apache-2.0
package services

import (
	"fmt"
	"net"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Dormant drafts need not contain complete credentials, but supplied sink
// values must still be safe. No files are read for a disabled profile path.
func validateDormantOpenVPN(cfg config.OpenVPNConfig) error {
	if cfg.Managed != nil {
		if _, err := validateOpenVPNClient(cfg.Managed, false); err != nil {
			return err
		}
	}
	if cfg.Server != nil {
		if _, err := validateOpenVPNServer(cfg.Server, false); err != nil {
			return err
		}
	}
	return nil
}

type openVPNManagedClientOptions struct {
	remote string
	port   int
	proto  string
	ca     string
	cert   string
	key    string
	user   string
	pass   string
}

func validateOpenVPNManagedClient(mc *config.OpenVPNManagedClientConfig) (openVPNManagedClientOptions, error) {
	return validateOpenVPNClient(mc, true)
}
func validateOpenVPNClient(mc *config.OpenVPNManagedClientConfig, required bool) (openVPNManagedClientOptions, error) {
	if mc == nil {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed config is nil")
	}
	if mc.Remote != "" {
		if err := config.ValidateOpenVPNRemote(mc.Remote); err != nil {
			return openVPNManagedClientOptions{}, err
		}
	}
	for _, v := range []string{mc.Username, mc.Password} {
		if v != "" {
			if err := config.ValidateOpenVPNAuthLine(v); err != nil {
				return openVPNManagedClientOptions{}, err
			}
		}
	}
	remote := strings.TrimSpace(mc.Remote)
	if required && remote == "" {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed remote is empty")
	}
	port := firstNonZeroPort(mc.Port, 1194)
	if err := validateOpenVPNPort("openvpn managed port", mc.Port, port); err != nil {
		return openVPNManagedClientOptions{}, err
	}
	proto, err := validateOpenVPNProto("openvpn managed proto", mc.Proto)
	if err != nil {
		return openVPNManagedClientOptions{}, err
	}
	if required && (strings.TrimSpace(mc.CA) == "" || strings.TrimSpace(mc.Cert) == "" || strings.TrimSpace(mc.Key) == "") {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed requires ca, cert, and key PEM blocks")
	}
	user := mc.Username
	pass := mc.Password
	if required && (user != "") != (pass != "") {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed username/password must be set together")
	}
	return openVPNManagedClientOptions{
		remote: remote,
		port:   port,
		proto:  proto,
		ca:     strings.TrimSpace(mc.CA),
		cert:   strings.TrimSpace(mc.Cert),
		key:    strings.TrimSpace(mc.Key),
		user:   user,
		pass:   pass,
	}, nil
}

type openVPNManagedServerOptions struct {
	port           int
	proto          string
	network        net.IP
	mask           string
	clientToClient bool
	pushDNS        []string
	pushRoutes     []string
}

func validateOpenVPNManagedServer(sc *config.OpenVPNManagedServerConfig) (openVPNManagedServerOptions, error) {
	return validateOpenVPNServer(sc, true)
}
func validateOpenVPNServer(sc *config.OpenVPNManagedServerConfig, required bool) (openVPNManagedServerOptions, error) {
	if sc == nil {
		return openVPNManagedServerOptions{}, errorsNew("openvpn server config is nil")
	}
	if sc.PublicEndpoint != "" {
		if err := config.ValidateOpenVPNRemote(sc.PublicEndpoint); err != nil {
			return openVPNManagedServerOptions{}, err
		}
	}
	for _, dns := range trimNonEmptyStrings(sc.PushDNS) {
		if ip := net.ParseIP(dns); ip == nil || ip.To4() == nil {
			return openVPNManagedServerOptions{}, fmt.Errorf("pushDNS must be IPv4")
		}
	}
	port := firstNonZeroPort(sc.ListenPort, 1194)
	if err := validateOpenVPNPort("openvpn server listenPort", sc.ListenPort, port); err != nil {
		return openVPNManagedServerOptions{}, err
	}
	proto, err := validateOpenVPNProto("openvpn server proto", sc.Proto)
	if err != nil {
		return openVPNManagedServerOptions{}, err
	}
	var network net.IP
	var mask string
	if required || sc.TunnelCIDR != "" {
		network, mask, err = validateOpenVPNTunnelCIDR(sc.TunnelCIDR)
		if err != nil {
			return openVPNManagedServerOptions{}, err
		}
	}
	pushRoutes, err := validateOpenVPNPushRoutes(sc.PushRoutes)
	if err != nil {
		return openVPNManagedServerOptions{}, err
	}
	return openVPNManagedServerOptions{
		port:           port,
		proto:          proto,
		network:        network,
		mask:           mask,
		clientToClient: sc.ClientToClient,
		pushDNS:        trimNonEmptyStrings(sc.PushDNS),
		pushRoutes:     pushRoutes,
	}, nil
}
