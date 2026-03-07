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
		// Skip header.
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		ifaceName := fields[0]
		dstHex := fields[1]
		gwHex := fields[2]
		metricStr := fields[6]
		maskHex := fields[7]

		dst, err := parseProcNetHexIPv4(dstHex)
		if err != nil {
			continue
		}
		gw, err := parseProcNetHexIPv4(gwHex)
		if err != nil {
			continue
		}
		mask, err := parseProcNetHexIPv4(maskHex)
		if err != nil {
			continue
		}

		ones, _ := net.IPMask(mask.To4()).Size()
		dstStr := fmt.Sprintf("%s/%d", dst.String(), ones)
		if dst.Equal(net.IPv4zero) && ones == 0 {
			dstStr = ""
		}

		gwStr := ""
		if !gw.Equal(net.IPv4zero) {
			gwStr = gw.String()
		}

		metric := 0
		if v, err := strconv.Atoi(metricStr); err == nil {
			metric = v
		}

		ifaceIdx := 0
		if iface, err := net.InterfaceByName(ifaceName); err == nil && iface != nil {
			ifaceIdx = iface.Index
		}

		routes = append(routes, ipv4Route{
			Dst:      dstStr,
			Gateway:  gwStr,
			IfIndex:  ifaceIdx,
			Priority: &metric,
		})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}

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

	return routes, nil
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
