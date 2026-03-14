// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

func listIPv4Routes() ([]ipv4Route, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	first := true

	var routes []ipv4Route
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		route, ok := parseProcNetRouteLine(line)
		if !ok {
			continue
		}
		routes = append(routes, route)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}

	sortIPv4Routes(routes)

	return routes, nil
}

func parseProcNetRouteLine(line string) (ipv4Route, bool) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return ipv4Route{}, false
	}

	dst, err := parseProcNetHexIPv4(fields[1])
	if err != nil {
		return ipv4Route{}, false
	}
	gateway, err := parseProcNetHexIPv4(fields[2])
	if err != nil {
		return ipv4Route{}, false
	}
	mask, err := parseProcNetHexIPv4(fields[7])
	if err != nil {
		return ipv4Route{}, false
	}
	return buildProcNetRoute(fields[0], dst, gateway, mask, fields[6]), true
}

func buildProcNetRoute(ifaceName string, dst, gateway, mask net.IP, metricStr string) ipv4Route {
	metric := 0
	if v, err := strconv.Atoi(metricStr); err == nil {
		metric = v
	}
	return ipv4Route{
		Dst:      procNetRouteDestination(dst, mask),
		Gateway:  procNetRouteGateway(gateway),
		IfIndex:  procNetInterfaceIndex(ifaceName),
		Priority: &metric,
	}
}

func procNetRouteDestination(dst, mask net.IP) string {
	ones, _ := net.IPMask(mask.To4()).Size()
	if dst.Equal(net.IPv4zero) && ones == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%d", dst.String(), ones)
}

func procNetRouteGateway(gateway net.IP) string {
	if gateway.Equal(net.IPv4zero) {
		return ""
	}
	return gateway.String()
}

func procNetInterfaceIndex(ifaceName string) int {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil || iface == nil {
		return 0
	}
	return iface.Index
}

func sortIPv4Routes(routes []ipv4Route) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Dst == "" && routes[j].Dst != "" {
			return true
		}
		if routes[i].Dst != "" && routes[j].Dst == "" {
			return false
		}
		if routes[i].IfIndex != routes[j].IfIndex {
			return routes[i].IfIndex < routes[j].IfIndex
		}
		return routes[i].Dst < routes[j].Dst
	})
}

func parseProcNetHexIPv4(hexLE string) (net.IP, error) {
	v, err := strconv.ParseUint(hexLE, 16, 32)
	if err != nil {
		return nil, err
	}
	b0 := byte(v & 0xff)
	b1 := byte((v >> 8) & 0xff)
	b2 := byte((v >> 16) & 0xff)
	b3 := byte((v >> 24) & 0xff)
	return net.IPv4(b0, b1, b2, b3), nil
}
