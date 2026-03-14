// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"net"
	"strings"

	"go.uber.org/zap"
)

func printStartupHints(logger *zap.SugaredLogger, httpAddr string, httpLoopbackAddr string, httpsAddr string, httpsLoopbackAddr string, enableHTTP bool, enableHTTPS bool, sshAddr string, sshEnabled bool) {
	httpPort := portOf(httpAddr)
	httpsPort := portOf(httpsAddr)
	sshPort := portOf(sshAddr)

	logger.Info("------------------------------------------------------------")
	logger.Info("containd access")

	if enableHTTP && httpPort != "" {
		logger.Infof("UI/API (HTTP):  http://localhost:%s", httpPort)
	}
	if enableHTTPS && httpsPort != "" {
		logger.Infof("UI/API (HTTPS): https://localhost:%s (self-signed by default)", httpsPort)
	}

	if sshEnabled && sshPort != "" {
		logger.Infof("SSH CLI: ssh -p %s containd@localhost", sshPort)
		logger.Info("         then type: wizard or menu")
	}

	ips := detectIPs()
	if len(ips) > 0 && httpPort != "" {
		logger.Infof("Container IPs: %s", strings.Join(ips, ", "))
		if enableHTTP && bindsAll(httpAddr) {
			for _, ip := range ips {
				logger.Infof("UI/API via IP (HTTP):  http://%s:%s", ip, httpPort)
				if sshEnabled && sshPort != "" {
					logger.Infof("SSH via IP:    ssh -p %s containd@%s", sshPort, ip)
				}
			}
		} else if enableHTTP && hostOnly(httpAddr) {
			logger.Infof("UI/API bind is restricted to %s; use localhost or reconfigure.", httpAddr)
		}
	}

	logger.Info("Initial login: username=containd password=containd (change immediately)")
	logger.Info("Production note: add SSH key and disable password auth after provisioning.")
	logger.Info("  - CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY=\"ssh-ed25519 AAAA...\"")
	logger.Info("Tip: docker compose logs -f containd")
	logger.Info("------------------------------------------------------------")
}

func portOf(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		_ = host
		return port
	}
	if i := strings.LastIndex(addr, ":"); i != -1 && i+1 < len(addr) {
		return strings.TrimSpace(addr[i+1:])
	}
	return ""
}

func bindsAll(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "" || h == "0.0.0.0" || h == "::" || h == "[::]"
}

func hostOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "localhost"
}

func detectIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := ipFromAddr(a)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if isRFC1918(ip4) {
					out = append(out, ip4.String())
				}
			}
		}
	}
	return out
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		_, ipnet, err := net.ParseCIDR(a.String())
		if err == nil && ipnet != nil {
			return ipnet.IP
		}
	}
	return nil
}

func isRFC1918(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	default:
		return false
	}
}
