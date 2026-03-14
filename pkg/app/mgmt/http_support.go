// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type ctxKey int

const localIPKey ctxKey = 1

func connContextWithLocalIP(ctx context.Context, c net.Conn) context.Context {
	if c == nil {
		return ctx
	}
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ctx
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ctx
	}
	return context.WithValue(ctx, localIPKey, ip)
}

func localIPFromRequest(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if v := r.Context().Value(localIPKey); v != nil {
		if ip, ok := v.(net.IP); ok {
			return ip
		}
	}
	return nil
}

func buildHTTPServers(handler http.Handler, addr string, loopbackAddr string) ([]*http.Server, []net.Listener, error) {
	var servers []*http.Server
	var listeners []net.Listener
	addrs := []string{addr}
	if loopbackAddr != "" && loopbackAddr != addr {
		addrs = append(addrs, loopbackAddr)
	}
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return nil, nil, err
		}
		srv := &http.Server{Handler: handler, ConnContext: connContextWithLocalIP}
		servers = append(servers, srv)
		listeners = append(listeners, ln)
	}
	return servers, listeners, nil
}

func buildHTTPSServers(handler http.Handler, addr string, loopbackAddr string, tlsCfg *tls.Config) ([]*http.Server, []net.Listener, error) {
	var servers []*http.Server
	var listeners []net.Listener
	addrs := []string{addr}
	if loopbackAddr != "" && loopbackAddr != addr {
		addrs = append(addrs, loopbackAddr)
	}
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return nil, nil, err
		}
		srv := &http.Server{Handler: handler, ConnContext: connContextWithLocalIP, TLSConfig: tlsCfg}
		servers = append(servers, srv)
		listeners = append(listeners, ln)
	}
	return servers, listeners, nil
}

type ipInterfaceIndex struct {
	mu         sync.RWMutex
	lastLoaded time.Time
	byIP       map[string]string
}

func newIPInterfaceIndex() *ipInterfaceIndex {
	return &ipInterfaceIndex{byIP: map[string]string{}}
}

func (idx *ipInterfaceIndex) lookup(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	key := ip4.String()

	idx.mu.RLock()
	if time.Since(idx.lastLoaded) < 30*time.Second {
		if v := idx.byIP[key]; v != "" {
			idx.mu.RUnlock()
			return v
		}
	}
	idx.mu.RUnlock()

	idx.refresh()

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byIP[key]
}

func (idx *ipInterfaceIndex) refresh() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if time.Since(idx.lastLoaded) < 30*time.Second {
		return
	}
	m := map[string]string{}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ip := ipFromAddr(a)
				if ip == nil {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					m[ip4.String()] = iface.Name
				}
			}
		}
	}
	idx.byIP = m
	idx.lastLoaded = time.Now()
}

func mgmtAccessHandler(store config.Store, idx *ipInterfaceIndex, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := localIPFromRequest(r)
		if ip == nil || ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}
		if store == nil {
			next.ServeHTTP(w, r)
			return
		}
		cfg, err := store.Load(r.Context())
		if err != nil || cfg == nil {
			next.ServeHTTP(w, r)
			return
		}
		ifaceName := ""
		if idx != nil {
			ifaceName = idx.lookup(ip)
		}
		allowed := mgmtAllowedOnInterface(cfg, ifaceName, r.TLS != nil)
		if !allowed {
			http.Error(w, "management access disabled on this interface", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mgmtAllowedOnInterface(cfg *config.Config, ifaceName string, isTLS bool) bool {
	if cfg == nil {
		return true
	}
	if ifaceName == "" {
		return true
	}
	for _, iface := range cfg.Interfaces {
		effectiveDev := strings.TrimSpace(iface.Device)
		if effectiveDev == "" {
			effectiveDev = iface.Name
		}
		if effectiveDev != ifaceName && iface.Name != ifaceName {
			continue
		}
		mgmt := boolDefault(iface.Access.Mgmt, true)
		if !mgmt {
			return false
		}
		if isTLS {
			return boolDefault(iface.Access.HTTPS, true)
		}
		return boolDefault(iface.Access.HTTP, true)
	}
	return true
}

func sshAllowedOnInterface(cfg *config.Config, ifaceName string) bool {
	if cfg == nil {
		return true
	}
	if ifaceName == "" {
		return true
	}
	for _, iface := range cfg.Interfaces {
		effectiveDev := strings.TrimSpace(iface.Device)
		if effectiveDev == "" {
			effectiveDev = iface.Name
		}
		if effectiveDev != ifaceName && iface.Name != ifaceName {
			continue
		}
		return boolDefault(iface.Access.SSH, true)
	}
	return true
}

func MgmtAllowedOnInterface(cfg *config.Config, ifaceName string, isTLS bool) bool {
	return mgmtAllowedOnInterface(cfg, ifaceName, isTLS)
}

func SSHAllowedOnInterface(cfg *config.Config, ifaceName string) bool {
	return sshAllowedOnInterface(cfg, ifaceName)
}
