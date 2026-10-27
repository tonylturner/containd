// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// A connection the scanning gate carries has two TCP legs, client→gate and
// gate→server, that the kernel never sees as one connection. A revocation
// or temporary block installed in nftables stops their packets but leaves
// both sockets open, so the engine tells the gate to reset the legs of
// every connection the installed rule covers.

// GateCloseRequest selects gated connections to reset. Host alone matches
// every connection with Host as an endpoint. Otherwise Src and Dst name a
// source and destination address, with ports that match any port when
// zero, and the request matches a connection whose client or upstream leg
// carries that tuple in either direction.
type GateCloseRequest struct {
	Host    netip.Addr
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
}

// GateCloser resets the gated connections a request matches and reports
// how many it closed.
type GateCloser interface {
	CloseMatching(req GateCloseRequest) int
}

type gateCloserBox struct{ closer GateCloser }

// gateCloser is the process's closer. A process runs one scanning gate
// beside its engine, and Reconfigure replaces the engine's members, so the
// closer is process state rather than a member of any one configuration.
var gateCloser atomic.Pointer[gateCloserBox]

// SetGateCloser installs the closer called after a revocation or a
// temporary block is installed; nil uninstalls it.
func SetGateCloser(c GateCloser) {
	gateCloser.Store(&gateCloserBox{closer: c})
}

// closeGated forwards requests to the installed closer, if any.
func closeGated(reqs []GateCloseRequest) {
	box := gateCloser.Load()
	if box == nil || box.closer == nil {
		return
	}
	for _, req := range reqs {
		box.closer.CloseMatching(req)
	}
}

// gateCloseRequests selects the gated connections a revocation of entries
// covers: the original tuple of every TCP entry, with the client port
// ignored under the client-service scope, as the revocation sets are.
func gateCloseRequests(entries []conntrack.Entry, scope string) []GateCloseRequest {
	var reqs []GateCloseRequest
	for _, e := range entries {
		if !strings.EqualFold(e.Proto, "tcp") {
			continue
		}
		src, err := netip.ParseAddr(e.Src)
		if err != nil {
			continue
		}
		dst, err := netip.ParseAddr(e.Dst)
		if err != nil {
			continue
		}
		req := GateCloseRequest{Src: src, Dst: dst, SrcPort: gatePort(e.Sport), DstPort: gatePort(e.Dport)}
		if scope == "client-service" {
			req.SrcPort = 0
		}
		reqs = append(reqs, req)
	}
	return reqs
}

// gateCloseForVerdict selects the gated connections a temporary block
// verdict covers: every connection of the blocked host, or the TCP flows to
// the blocked destination. A block on another transport covers no gated
// connection, which is always TCP.
func gateCloseForVerdict(v verdict.Verdict, flow rules.EvalContext) (GateCloseRequest, bool) {
	switch v.Action {
	case verdict.BlockHostTemp:
		ip := flow.SrcIP
		if ip == nil {
			ip = flow.DstIP
		}
		host, ok := netip.AddrFromSlice(ip)
		if !ok {
			return GateCloseRequest{}, false
		}
		return GateCloseRequest{Host: host.Unmap()}, true
	case verdict.BlockFlowTemp:
		if !strings.EqualFold(flow.Proto, "tcp") {
			return GateCloseRequest{}, false
		}
		src, okSrc := netip.AddrFromSlice(flow.SrcIP)
		dst, okDst := netip.AddrFromSlice(flow.DstIP)
		if !okSrc || !okDst {
			return GateCloseRequest{}, false
		}
		return GateCloseRequest{Src: src.Unmap(), Dst: dst.Unmap(), DstPort: gatePort(flow.Port)}, true
	default:
		return GateCloseRequest{}, false
	}
}

// gatePort parses a decimal port; anything else matches any port.
func gatePort(text string) uint16 {
	p, err := strconv.ParseUint(strings.TrimSpace(text), 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}
