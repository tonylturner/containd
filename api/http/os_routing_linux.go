// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package httpapi

import (
	"bufio"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type osRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway,omitempty"`
	Iface   string `json:"iface,omitempty"`
	Metric  *int   `json:"metric,omitempty"`
}

type osRoutingSnapshot struct {
	Routes       []osRoute `json:"routes"`
	DefaultRoute *osRoute  `json:"defaultRoute,omitempty"`
}

func getOSRoutingHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		st, err := readProcNetRoute()
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(200, st)
	}
}

func readProcNetRoute() (*osRoutingSnapshot, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	first := true

	var routes []osRoute
	var def *osRoute

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		r, isDefault, ok := parseProcRouteLine(fields)
		if !ok {
			continue
		}
		routes = append(routes, r)
		if isDefault && def == nil {
			rr := r
			def = &rr
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Dst == "default" && routes[j].Dst != "default" {
			return true
		}
		if routes[i].Dst != "default" && routes[j].Dst == "default" {
			return false
		}
		if routes[i].Iface != routes[j].Iface {
			return routes[i].Iface < routes[j].Iface
		}
		return routes[i].Dst < routes[j].Dst
	})

	return &osRoutingSnapshot{Routes: routes, DefaultRoute: def}, nil
}

func parseProcRouteLine(fields []string) (osRoute, bool, bool) {
	if len(fields) < 8 {
		return osRoute{}, false, false
	}
	dst, gw, ones, ok := parseProcRouteNetwork(fields[1], fields[2], fields[7])
	if !ok {
		return osRoute{}, false, false
	}
	route := osRoute{
		Dst:     routeDestination(dst, ones),
		Gateway: routeGateway(gw),
		Iface:   fields[0],
		Metric:  routeMetric(fields[6]),
	}
	return route, route.Dst == "default" && route.Gateway != "", true
}

func parseProcRouteNetwork(dstHex, gwHex, maskHex string) (net.IP, net.IP, int, bool) {
	dst, err := parseProcNetHexIPv4(dstHex)
	if err != nil {
		return nil, nil, 0, false
	}
	gw, err := parseProcNetHexIPv4(gwHex)
	if err != nil {
		return nil, nil, 0, false
	}
	mask, err := parseProcNetHexIPv4(maskHex)
	if err != nil {
		return nil, nil, 0, false
	}
	ones, _ := net.IPMask(mask.To4()).Size()
	return dst, gw, ones, true
}

func routeDestination(dst net.IP, ones int) string {
	if dst.Equal(net.IPv4zero) && ones == 0 {
		return "default"
	}
	return dst.String() + "/" + strconv.Itoa(ones)
}

func routeGateway(gw net.IP) string {
	if gw.Equal(net.IPv4zero) {
		return ""
	}
	return gw.String()
}

func routeMetric(raw string) *int {
	if v, err := strconv.Atoi(raw); err == nil {
		return &v
	}
	return nil
}

func detectKernelDefaultRouteIface() string {
	st, err := readProcNetRoute()
	if err != nil || st == nil || st.DefaultRoute == nil {
		return ""
	}
	return strings.TrimSpace(st.DefaultRoute.Iface)
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
