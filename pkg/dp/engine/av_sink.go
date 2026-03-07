// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

// AVSink receives HTTP request/response previews for asynchronous scanning.
// Implementations should return quickly; heavy lifting should be async.
type AVSink interface {
	EnqueueAVScan(ctx context.Context, task AVScanTask)
}

// AVScanTask describes a preview to scan.
type AVScanTask struct {
	Hash      string
	Direction string // request|response
	Proto     string
	Source    string
	Dest      string
	FlowID    string
	Preview   []byte
	ICS       bool
}

// SetAVSink installs an optional sink for HTTP previews.
func (e *Engine) SetAVSink(s AVSink) {
	if e == nil {
		return
	}
	e.avSink = s
}

func srcDestStrings(state *flow.State) (string, string) {
	if state == nil {
		return "", ""
	}
	src := state.Key.SrcIP.String()
	if state.Key.SrcPort > 0 {
		src = src + ":" + strconv.Itoa(int(state.Key.SrcPort))
	}
	dst := state.Key.DstIP.String()
	if state.Key.DstPort > 0 {
		dst = dst + ":" + strconv.Itoa(int(state.Key.DstPort))
	}
	return src, dst
}

// splitHostPort parses host:port strings and returns srcIP, dstIP, dport, proto.
func splitHostPort(src, dst string) (net.IP, net.IP, string, string) {
	srcHost, _, _ := strings.Cut(src, ":")
	dstHost, dstPort, _ := strings.Cut(dst, ":")
	sip := net.ParseIP(strings.TrimSpace(srcHost))
	dip := net.ParseIP(strings.TrimSpace(dstHost))
	return sip, dip, strings.TrimSpace(dstPort), "tcp"
}
