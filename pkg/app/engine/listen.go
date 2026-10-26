// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// ListenAddr resolves the engine listener for both planes: CONTAIND_ENGINE_ADDR,
// else loopback in combined mode, where management shares the process. Split
// mode has no default; see engineListener.
func ListenAddr(combined bool) string {
	if addr := common.EnvTrimmed("CONTAIND_ENGINE_ADDR", ""); addr != "" {
		return addr
	}
	if combined {
		return "127.0.0.1:8081"
	}
	return ""
}

// splitListenerHint tells a split-mode operator which listener to set.
const splitListenerHint = "set CONTAIND_ENGINE_ADDR to this engine's address on the management network, for example 192.0.2.10:8081"

// engineListener checks the engine API listener addr and returns the path
// enforcement admits to it besides loopback. The API is unauthenticated, so a
// split-mode engine must bind the one address management uses to reach it:
// a wildcard listener would serve every zone without enforcement and only
// loopback with it, and a loopback listener is out of reach of a management
// process elsewhere. The exception is a reserved management path, which puts
// both processes in one network namespace and requires a loopback engine.
func engineListener(addr string, combined bool, r *mgmtpath.Reservation, nics map[string][]netip.Addr) (*enforce.EngineAPIPath, error) {
	if addr == "" {
		return nil, fmt.Errorf("engine mode requires a listener: %s", splitListenerHint)
	}
	if err := r.ValidateEngineBind(addr); err != nil {
		return nil, err
	}
	path, err := engineAPIPath(addr, nics)
	if err != nil {
		return nil, err
	}
	if !combined && r == nil && path == nil {
		return nil, fmt.Errorf("engine mode refuses listener %q on loopback or every address: %s", addr, splitListenerHint)
	}
	return path, nil
}

// engineAPIPath returns the path enforcement admits to the API listening on
// addr besides loopback: addr's address on the interface in nics that holds
// it. A listener on loopback or on every address has none, so enforcement
// admits the API from loopback only.
func engineAPIPath(addr string, nics map[string][]netip.Addr) (*enforce.EngineAPIPath, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("engine listener %q: %w", addr, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, fmt.Errorf("engine listener %q: want a numeric TCP port", addr)
	}
	if host == "" || host == "localhost" {
		return nil, nil
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("engine listener %q: want an IP address", addr)
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return nil, nil
	}
	var devices []string
	for name, addrs := range nics {
		if slices.Contains(addrs, a) {
			devices = append(devices, name)
		}
	}
	if len(devices) != 1 {
		return nil, fmt.Errorf("engine listener %q: want one interface holding %s, found %d", addr, a, len(devices))
	}
	return &enforce.EngineAPIPath{Device: devices[0], Addr: a, Port: uint16(p)}, nil
}

// interfaceAddrs maps each interface to its addresses.
func interfaceAddrs() (map[string][]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	nics := make(map[string][]netip.Addr, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				nics[i.Name] = append(nics[i.Name], p.Addr().Unmap())
			}
		}
	}
	return nics, nil
}
