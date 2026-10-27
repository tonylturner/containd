// SPDX-License-Identifier: Apache-2.0

package conntrack

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// KillRequest selects the original tuple displayed by List. A connection scope
// allows a new source port, or a new ICMP identifier; client-service ends all
// of this client's connections to the service and prevents new ones for the
// interval. An ICMP or ICMPv6 service is the query type and code sent to the
// destination, so client-service ends all of the client's pings to that host.
type KillRequest struct {
	DeleteRequest
	Scope        string `json:"scope,omitempty"`
	DurationSecs int    `json:"durationSecs,omitempty"`
}

type KillResult struct {
	Scope               string     `json:"scope"`
	Matched             int        `json:"matched"`
	Deleted             int        `json:"deleted"`
	ConntrackDeleted    bool       `json:"conntrackDeleted"`
	DeleteError         string     `json:"deleteError,omitempty"`
	RevocationInstalled bool       `json:"revocationInstalled"`
	RevocationError     string     `json:"revocationError,omitempty"`
	BlockedUntil        *time.Time `json:"blockedUntil,omitempty"`
	Closure             string     `json:"closure"`
}

// icmpQueries are the ICMP and ICMPv6 types that open a conntrack entry: the
// original tuple of every ICMP entry carries one of them.
var icmpQueries = map[string][]int{"icmp": {8, 13, 15, 17}, "icmpv6": {128, 139}}

func (r *KillRequest) Validate() error {
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	if r.Proto != "tcp" && r.Proto != "udp" && !IsICMP(r.Proto) {
		return fmt.Errorf("kill requires tcp, udp, icmp or icmpv6 with a complete tuple")
	}
	src, e1 := netip.ParseAddr(r.Src)
	dst, e2 := netip.ParseAddr(r.Dst)
	if e1 != nil || e2 != nil || src.Is4() != dst.Is4() || src.Zone() != "" || dst.Zone() != "" {
		return fmt.Errorf("invalid or mixed-family endpoints")
	}
	r.Src = src.String()
	r.Dst = dst.String()
	if err := r.validateTuple(src.Is4()); err != nil {
		return err
	}
	if r.Scope == "" {
		r.Scope = "connection"
	}
	if r.Scope != "connection" && r.Scope != "client-service" {
		return fmt.Errorf("scope must be connection or client-service")
	}
	if r.DurationSecs == 0 {
		r.DurationSecs = 60
	}
	if r.DurationSecs < 1 || r.DurationSecs > 3600 {
		return fmt.Errorf("durationSecs must be between 1 and 3600")
	}
	return nil
}

// validateTuple checks the transport fields of the tuple: ports for TCP and
// UDP, identifier, query type and code for ICMP (IPv4) and ICMPv6 (IPv6).
func (r *KillRequest) validateTuple(ipv4 bool) error {
	if !IsICMP(r.Proto) {
		if r.ICMPID != 0 || r.ICMPType != 0 || r.ICMPCode != 0 {
			return fmt.Errorf("icmpId, icmpType and icmpCode apply only to icmp and icmpv6")
		}
		if r.Sport < 1 || r.Sport > 65535 || r.Dport < 1 || r.Dport > 65535 {
			return fmt.Errorf("ports must be between 1 and 65535")
		}
		return nil
	}
	if (r.Proto == "icmp") != ipv4 {
		return fmt.Errorf("icmp needs IPv4 endpoints and icmpv6 IPv6 endpoints")
	}
	if r.Sport != 0 || r.Dport != 0 {
		return fmt.Errorf("%s has no ports; select it by icmpId, icmpType and icmpCode", r.Proto)
	}
	if r.ICMPID < 0 || r.ICMPID > 65535 || r.ICMPCode < 0 || r.ICMPCode > 255 {
		return fmt.Errorf("icmpId must be between 0 and 65535 and icmpCode between 0 and 255")
	}
	if !slices.Contains(icmpQueries[r.Proto], r.ICMPType) {
		return fmt.Errorf("icmpType must be a %s query type that opens a connection: %v", r.Proto, icmpQueries[r.Proto])
	}
	return nil
}

// sameService reports whether e has the request's protocol, endpoints and
// service: the destination port, or the ICMP type and code.
func (r *KillRequest) sameService(e Entry) bool {
	if e.Proto != r.Proto || e.Src != r.Src || e.Dst != r.Dst {
		return false
	}
	if IsICMP(r.Proto) {
		return e.ICMPType == strconv.Itoa(r.ICMPType) && e.ICMPCode == strconv.Itoa(r.ICMPCode)
	}
	return e.Dport == strconv.Itoa(r.Dport)
}

// sameConnection reports whether e is the selected connection: its service
// and its source port or ICMP identifier.
func (r *KillRequest) sameConnection(e Entry) bool {
	if !r.sameService(e) {
		return false
	}
	if IsICMP(r.Proto) {
		return e.ICMPID == strconv.Itoa(r.ICMPID)
	}
	return e.Sport == strconv.Itoa(r.Sport)
}

type RevokeFunc func(context.Context, []Entry, string, time.Duration) error

// Kill installs the revocation before deleting state so no packet can escape
// between deletion and blocking. A partial result is returned even on failure.
func Kill(ctx context.Context, req KillRequest, revoke RevokeFunc) (KillResult, error) {
	return kill(ctx, req, revoke, List, Delete)
}
func kill(ctx context.Context, req KillRequest, revoke RevokeFunc, list func(context.Context, int) ([]Entry, error), del func(context.Context, DeleteRequest) error) (KillResult, error) {
	result := KillResult{Closure: "not signalled"}
	if err := req.Validate(); err != nil {
		return result, err
	}
	result.Scope = req.Scope
	entries, err := list(ctx, 0)
	if err != nil {
		return result, err
	}
	selected := []Entry{}
	found := false
	for _, e := range entries {
		if !req.sameService(e) {
			continue
		}
		exact := req.sameConnection(e)
		found = found || exact
		if req.Scope == "client-service" || exact {
			selected = append(selected, e)
		}
	}
	if !found {
		return result, fmt.Errorf("selected connection not found; refresh the connections view")
	}
	result.Matched = len(selected)
	// This timestamp is conservative: the kernel timeout starts after this instant.
	until := time.Now().UTC().Add(time.Duration(req.DurationSecs) * time.Second)
	if err := revoke(ctx, selected, req.Scope, time.Duration(req.DurationSecs)*time.Second); err != nil {
		result.RevocationError = err.Error()
		return result, nil
	}
	result.RevocationInstalled = true
	result.BlockedUntil = &until
	result.Closure = "matching packets dropped"
	if req.Proto == "tcp" {
		result.Closure = "TCP reset signalled on each endpoint's next packet; closure not confirmed"
	}
	for _, e := range selected {
		original, err := e.Original()
		if err == nil {
			err = del(ctx, original)
		}
		if err != nil {
			result.DeleteError = err.Error()
		} else {
			result.Deleted++
		}
	}
	result.ConntrackDeleted = result.Deleted == result.Matched
	return result, nil
}
