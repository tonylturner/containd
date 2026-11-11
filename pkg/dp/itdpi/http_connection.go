// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

const maxHTTPRequestMethods = 64

type httpRequest struct {
	method, upgrade string
}

type httpConnection struct {
	refs        int
	client      httpStreamKey
	clientKnown bool
	methods     []httpRequest
	// Extra requests need only a scalar count, not retained metadata. Until
	// all outstanding replies arrive, inspect headers without body framing or
	// tunnel transitions. Saturation keeps this conservative mode permanent.
	dropped uint64
	opaque  bool
}

func (c *httpConnection) acceptsStart(key httpStreamKey, response bool) bool {
	if key.dir != dpi.DirUnknown {
		return response == (key.dir == dpi.ServerToClient)
	}
	return !c.clientKnown || response != (key == c.client)
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
	if c.dropped == 0 && len(c.methods) > 0 {
		return c.methods[0]
	}
	return httpRequest{}
}

func (c *httpConnection) response() {
	if len(c.methods) > 0 {
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
	for part := range strings.SplitSeq(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
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
	name, version, versioned := strings.Cut(strings.TrimSpace(value), "/")
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
