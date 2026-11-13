// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"bytes"
	"net/url"
	"strings"
	"sync"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// HTTPDecoder emits minimal plaintext HTTP request/response metadata. It
// never attaches raw payload bytes: headers and bodies carry credentials,
// cookies and content that must not reach the event store or its exports.
type HTTPDecoder struct {
	mu          sync.Mutex
	resources   limits.Resources
	serial      uint64
	streams     map[httpStreamKey]*httpStream
	connections map[string]*httpConnection
}

func NewHTTPDecoder() *HTTPDecoder {
	return &HTTPDecoder{resources: limits.NewResources(nil, nil)}
}

// Ports implements dpi.PortHinter for port-based dispatch.
func (d *HTTPDecoder) Ports() (tcpPorts, udpPorts []uint16) {
	return []uint16{80, 8080, 8000, 3128}, nil
}

func (d *HTTPDecoder) Supports(state *flow.State) bool {
	if state == nil || state.Key.Proto != 6 {
		return false
	}
	// Common plaintext HTTP/proxy ports.
	switch state.Key.SrcPort {
	case 80, 8080, 8000, 3128:
		return true
	}
	switch state.Key.DstPort {
	case 80, 8080, 8000, 3128:
		return true
	}
	return false
}

func (d *HTTPDecoder) OnPacket(state *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if pkt == nil || len(pkt.Payload) == 0 {
		return nil, nil
	}
	// Packet-local callers have no TCP offsets. Stream-aware callers go through
	// the manager, which owns reassembly and the decoder lifetime.
	local := NewHTTPDecoder()
	d.mu.Lock()
	local.SetResources(d.resources)
	d.mu.Unlock()
	defer local.StreamEnded("", dpi.DirUnknown)
	res, err := local.ParseStream(state, dpi.StreamView{Bytes: pkt.Payload, Role: pkt.Role, HasPacketStart: true})
	var events []dpi.Event
	for _, f := range res.Frames {
		events = append(events, f.Events...)
	}
	return events, err
}

func http1Events(state *flow.State, pkt *dpi.ParsedPacket) []dpi.Event {
	line, headers := parseHTTP(pkt.Payload)
	if line == "" {
		return nil
	}
	if strings.HasPrefix(line, "HTTP/") {
		parts := strings.SplitN(line, " ", 3)
		status := ""
		if len(parts) > 1 {
			status = parts[1]
		}
		attrs := map[string]any{
			"status":       status,
			"content_type": headers["content-type"],
			"transport":    pkt.Proto,
			"src_port":     pkt.SrcPort,
			"dst_port":     pkt.DstPort,
		}
		ev := dpi.Event{FlowID: state.ID(), Proto: "http", Kind: "response", Attributes: attrs}
		return []dpi.Event{ev}
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil
	}
	method := parts[0]
	path := parts[1]
	host := headers["host"]
	scheme := ""
	targetHost := host
	// Absolute-form URL (common for proxies).
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		if u, err := url.Parse(path); err == nil {
			scheme = u.Scheme
			targetHost = u.Host
			path = u.Path
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
		}
	}
	// CONNECT host:port for HTTPS proxying.
	if strings.EqualFold(method, "CONNECT") {
		targetHost = parts[1]
	}
	ua := headers["user-agent"]
	attrs := map[string]any{
		"method":       method,
		"content_type": headers["content-type"],
		"path":         path,
		"host":         host,
		"target":       targetHost,
		"scheme":       scheme,
		"user_agent":   ua,
		"transport":    pkt.Proto,
		"src_port":     pkt.SrcPort,
		"dst_port":     pkt.DstPort,
	}
	ev := dpi.Event{FlowID: state.ID(), Proto: "http", Kind: "request", Attributes: attrs}
	return []dpi.Event{ev}
}

func (d *HTTPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

func parseHTTP(payload []byte) (string, map[string]string) {
	firstEnd := bytes.IndexByte(payload, '\n')
	if firstEnd < 0 {
		return "", nil
	}
	first := strings.TrimSuffix(string(payload[:firstEnd]), "\r")
	if !looksLikeHTTPLine(first) {
		return "", nil
	}
	headers := map[string]string{}
	rest := payload[firstEnd+1:]
	for {
		end := bytes.IndexByte(rest, '\n')
		if end < 0 {
			break
		}
		l := strings.Trim(strings.TrimSuffix(string(rest[:end]), "\r"), " \t")
		rest = rest[end+1:]
		if l == "" {
			break
		}
		kv := strings.SplitN(l, ":", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.Trim(kv[0], " \t"))
		v := strings.Trim(kv[1], " \t")
		switch k {
		case "upgrade", "connection", "transfer-encoding":
			if previous, ok := headers[k]; ok {
				v = previous + "," + v
			}
		}
		headers[k] = v
	}
	return first, headers
}

func looksLikeHTTPLine(l string) bool {
	_, valid := httpStart([]byte(l + "\n"))
	return valid
}
