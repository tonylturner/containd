// SPDX-License-Identifier: Apache-2.0

package conntrack

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// KillRequest selects the original tuple displayed by List. A connection scope
// allows a new source port; client-service ends all of this client's connections
// to the service and prevents new ones for the interval.
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

func (r *KillRequest) Validate() error {
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	if r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("kill requires tcp or udp with a complete tuple")
	}
	src, e1 := netip.ParseAddr(r.Src)
	dst, e2 := netip.ParseAddr(r.Dst)
	if e1 != nil || e2 != nil || src.Is4() != dst.Is4() || src.Zone() != "" || dst.Zone() != "" {
		return fmt.Errorf("invalid or mixed-family endpoints")
	}
	r.Src = src.String()
	r.Dst = dst.String()
	if r.Sport < 1 || r.Sport > 65535 || r.Dport < 1 || r.Dport > 65535 {
		return fmt.Errorf("ports must be between 1 and 65535")
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
		if e.Proto != req.Proto || e.Src != req.Src || e.Dst != req.Dst || e.Dport != strconv.Itoa(req.Dport) {
			continue
		}
		if e.Sport == strconv.Itoa(req.Sport) {
			found = true
		}
		if req.Scope == "client-service" || e.Sport == strconv.Itoa(req.Sport) {
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
		sport, _ := strconv.Atoi(e.Sport)
		dport, _ := strconv.Atoi(e.Dport)
		err := del(ctx, DeleteRequest{Proto: e.Proto, Src: e.Src, Dst: e.Dst, Sport: sport, Dport: dport})
		if err != nil {
			result.DeleteError = err.Error()
		} else {
			result.Deleted++
		}
	}
	result.ConntrackDeleted = result.Deleted == result.Matched
	return result, nil
}
