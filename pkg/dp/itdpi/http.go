// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// HTTPDecoder emits minimal plaintext HTTP request/response metadata. It
// never attaches raw payload bytes: headers and bodies carry credentials,
// cookies and content that must not reach the event store or its exports.
type HTTPDecoder struct{}

func NewHTTPDecoder() *HTTPDecoder { return &HTTPDecoder{} }

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
	// HTTP/2 cleartext preface.
	if bytes.HasPrefix(pkt.Payload, []byte("PRI * HTTP/2.0")) {
		ev := dpi.Event{
			FlowID: state.ID(),
			Proto:  "http2",
			Kind:   "preface",
			Attributes: map[string]any{
				"transport": pkt.Proto,
				"src_port":  pkt.SrcPort,
				"dst_port":  pkt.DstPort,
			},
		}
		return []dpi.Event{ev}, nil
	}
	line, headers := parseHTTP(pkt.Payload)
	if line == "" {
		return nil, nil
	}
	if strings.HasPrefix(line, "HTTP/") {
		parts := strings.SplitN(line, " ", 3)
		status := ""
		if len(parts) > 1 {
			status = parts[1]
		}
		attrs := map[string]any{
			"status":    status,
			"transport": pkt.Proto,
			"src_port":  pkt.SrcPort,
			"dst_port":  pkt.DstPort,
		}
		ev := dpi.Event{FlowID: state.ID(), Proto: "http", Kind: "response", Attributes: attrs}
		return []dpi.Event{ev}, nil
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, nil
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
		"method":     method,
		"path":       path,
		"host":       host,
		"target":     targetHost,
		"scheme":     scheme,
		"user_agent": ua,
		"transport":  pkt.Proto,
		"src_port":   pkt.SrcPort,
		"dst_port":   pkt.DstPort,
	}
	ev := dpi.Event{FlowID: state.ID(), Proto: "http", Kind: "request", Attributes: attrs}
	return []dpi.Event{ev}, nil
}

func (d *HTTPDecoder) OnFlowEnd(state *flow.State) ([]dpi.Event, error) { return nil, nil }

func parseHTTP(payload []byte) (string, map[string]string) {
	firstEnd := bytes.IndexByte(payload, '\n')
	if firstEnd < 0 {
		return "", nil
	}
	first := strings.TrimSpace(string(payload[:firstEnd]))
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
		l := strings.TrimSpace(string(rest[:end]))
		rest = rest[end+1:]
		if l == "" {
			break
		}
		kv := strings.SplitN(l, ":", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		headers[k] = v
	}
	return first, headers
}

func looksLikeHTTPLine(l string) bool {
	if strings.HasPrefix(l, "HTTP/") {
		return true
	}
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH "}
	for _, m := range methods {
		if strings.HasPrefix(l, m) {
			return true
		}
	}
	return false
}
