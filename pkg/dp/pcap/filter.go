// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package pcap

import (
	"net"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func matchFilter(data []byte, filter config.PCAPFilter) bool {
	proto := strings.ToLower(strings.TrimSpace(filter.Proto))
	src := strings.TrimSpace(filter.Src)
	dst := strings.TrimSpace(filter.Dst)
	port := strings.TrimSpace(filter.Port)
	if proto == "" || proto == "any" {
		proto = ""
	}
	if src == "" && dst == "" && proto == "" && port == "" {
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
	if data[14]>>4 != 4 {
		return false
	}
	ipHeaderLen := int(data[14]&0x0f) * 4
	if ipHeaderLen < 20 || len(data) < 14+ipHeaderLen {
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
	if port != "" {
		if ipProto != 6 && ipProto != 17 {
			return false
		}
		minPort, maxPort, err := config.ParsePCAPPortRange(port)
		if err != nil {
			return false
		}
		fragment := (uint16(data[20]&0x1f) << 8) | uint16(data[21])
		if fragment&0x1fff != 0 {
			return false
		}
		portOffset := 14 + ipHeaderLen
		ipTotalLen := int(data[16])<<8 | int(data[17])
		if ipTotalLen < ipHeaderLen+4 || len(data) < portOffset+4 {
			return false
		}
		srcPort := uint16(data[portOffset])<<8 | uint16(data[portOffset+1])
		dstPort := uint16(data[portOffset+2])<<8 | uint16(data[portOffset+3])
		if !portInRange(srcPort, minPort, maxPort) && !portInRange(dstPort, minPort, maxPort) {
			return false
		}
	}
	return true
}

func portInRange(port, min, max uint16) bool {
	return port >= min && port <= max
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
