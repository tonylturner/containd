// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func (c *httpConnection) role(key httpStreamKey) dpi.StreamDir {
	if c.transportRole == dpi.DirUnknown || key == c.transportKey {
		return c.transportRole
	}
	if c.transportRole == dpi.ClientToServer {
		return dpi.ServerToClient
	}
	return dpi.ClientToServer
}

const maxHTTPRequestMethods = 64

type httpRequest struct {
	method, upgrade string
	body            *httpBody
}

type httpBody struct {
	incomplete, rejected bool
}

type httpConnection struct {
	streams     map[httpStreamKey]*httpStream
	client      httpStreamKey
	clientKnown bool
	methods     []httpRequest
	// Extra requests retain only a count. The retained prefix still owns its
	// real response boundaries; speculative re-anchors never restore trust.
	dropped       uint64
	uncertain     bool
	server        httpStreamKey
	serverKnown   bool
	transportKey  httpStreamKey
	transportRole dpi.StreamDir
}

func (c *httpConnection) acceptsStart(key httpStreamKey, response bool) bool {
	if c.clientKnown {
		return response != (key == c.client)
	}
	return !c.serverKnown || response == (key == c.server)
}

func (c *httpConnection) request(key httpStreamKey, method string, headers map[string]string) {
	if !c.clientKnown {
		c.client, c.clientKnown = key, true
	}
	if c.dropped != 0 || len(c.methods) == maxHTTPRequestMethods {
		if c.dropped != ^uint64(0) {
			c.dropped++
		}
		return
	}
	// Retain only correlation fields, never the backing request line/path.
	r := httpRequest{method: strings.Clone(method)}
	if httpHeaderToken(headers["connection"], "upgrade") {
		r.upgrade = strings.Clone(headers["upgrade"])
	}
	c.methods = append(c.methods, r)
}

func (c *httpConnection) pending() httpRequest {
	if len(c.methods) > 0 {
		return c.methods[0]
	}
	return httpRequest{}
}

func (c *httpConnection) response() {
	if len(c.methods) > 0 {
		if b := c.methods[0].body; b != nil && b.incomplete && !c.uncertain {
			b.rejected = true
		}
		c.methods[0] = httpRequest{}
		c.methods = c.methods[1:]
		if len(c.methods) == 0 {
			c.methods = nil
		}
	} else if c.dropped != 0 && c.dropped != ^uint64(0) {
		c.dropped--
	}
}

func httpHeaderToken(value, token string) bool {
	found := false
	for part := range strings.SplitSeq(value, ",") {
		part = strings.Trim(part, " \t")
		if part != "" && !httpProtocolToken(part) {
			return false
		}
		found = found || strings.EqualFold(part, token)
	}
	return found
}

func (r httpRequest) acceptsUpgrade(headers map[string]string) bool {
	selected := headers["upgrade"]
	if selected == "" || r.upgrade == "" || !httpHeaderToken(headers["connection"], "upgrade") {
		return false
	}
	// RFC 9110 7.8 permits multiple selected protocol layers. Every layer
	// must have been offered; names compare case-insensitively, not versions.
	// A set keeps work linear in the bounded request/response header lengths.
	offered := make(map[string]struct{})
	for protocol := range strings.SplitSeq(r.upgrade, ",") {
		if key := httpUpgradeProtocol(protocol); key != "" {
			offered[key] = struct{}{}
		}
	}
	for protocol := range strings.SplitSeq(selected, ",") {
		key := httpUpgradeProtocol(protocol)
		if _, ok := offered[key]; key == "" || !ok {
			return false
		}
	}
	return true
}

func httpUpgradeProtocol(value string) string {
	name, version, versioned := strings.Cut(strings.Trim(value, " \t"), "/")
	if !httpProtocolToken(name) || versioned && !httpProtocolToken(version) {
		return ""
	}
	if versioned {
		return strings.ToLower(name) + "/" + version
	}
	return strings.ToLower(name)
}

func httpProtocolToken(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}
