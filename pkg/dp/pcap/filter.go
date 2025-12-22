package pcap

import (
	"net"
	"strings"

	"github.com/containd/containd/pkg/cp/config"
)

func matchFilter(data []byte, filter config.PCAPFilter) bool {
	proto := strings.ToLower(strings.TrimSpace(filter.Proto))
	src := strings.TrimSpace(filter.Src)
	dst := strings.TrimSpace(filter.Dst)
	if proto == "" || proto == "any" {
		proto = ""
	}
	if src == "" && dst == "" && proto == "" {
		return true
	}
	if len(data) < 14 {
		return false
	}
	ethType := (uint16(data[12]) << 8) | uint16(data[13])
	if ethType != 0x0800 {
		return false
	}
	if len(data) < 34 {
		return false
	}
	ipHeaderLen := int(data[14]&0x0f) * 4
	if len(data) < 14+ipHeaderLen {
		return false
	}
	ipProto := data[23]
	if proto != "" && !matchProto(proto, ipProto) {
		return false
	}
	srcIP := net.IP(data[26:30])
	dstIP := net.IP(data[30:34])
	if src != "" && !matchIP(src, srcIP) {
		return false
	}
	if dst != "" && !matchIP(dst, dstIP) {
		return false
	}
	return true
}

func matchProto(proto string, ipProto byte) bool {
	switch proto {
	case "tcp":
		return ipProto == 6
	case "udp":
		return ipProto == 17
	case "icmp":
		return ipProto == 1
	default:
		return false
	}
}

func matchIP(spec string, ip net.IP) bool {
	if strings.Contains(spec, "/") {
		_, cidr, err := net.ParseCIDR(spec)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}
	target := net.ParseIP(spec)
	if target == nil {
		return false
	}
	return target.Equal(ip)
}
