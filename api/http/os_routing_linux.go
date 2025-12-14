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
			c.JSON(500, gin.H{"error": err.Error()})
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
		// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
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

		dstStr := dst.String() + "/" + strconv.Itoa(ones)
		if dst.Equal(net.IPv4zero) && ones == 0 {
			dstStr = "default"
		}

		gwStr := ""
		if !gw.Equal(net.IPv4zero) {
			gwStr = gw.String()
		}

		var metricPtr *int
		if v, err := strconv.Atoi(metricStr); err == nil {
			metricPtr = &v
		}

		r := osRoute{
			Dst:     dstStr,
			Gateway: gwStr,
			Iface:   ifaceName,
			Metric:  metricPtr,
		}
		routes = append(routes, r)
		if dstStr == "default" && gwStr != "" && def == nil {
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

