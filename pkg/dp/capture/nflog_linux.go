// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	nflog "github.com/florianl/go-nflog/v2"

	"github.com/tonylturner/containd/pkg/dp/events"
)

// RuleHitSink receives firewall.rule.hit events derived from kernel nflog
// messages. Implemented by *events.Store (Append). Defined as an interface
// so the capture package doesn't take a hard dep on the engine for tests.
type RuleHitSink interface {
	Append(e events.Event) events.Event
}

// nflog log-prefix shape produced by enforce.logPrefix:
//
//	containd:<sanitized-id>:<ACTION><space>
//
// The producer sanitizes rule IDs to [A-Za-z0-9_-] at log-prefix time,
// so the consumer-side regex restricts to the same character set. This
// ensures rule IDs containing `:` (which would otherwise be valid per
// config validation) don't silently get dropped here. The trailing
// space is consumed by \s* and then anchored by $.
var rulePrefixRE = regexp.MustCompile(`^containd:([A-Za-z0-9_-]+):([A-Z]+)\s*$`)

// StartNFLog opens an nflog subscription on the given group and emits a
// firewall.rule.hit event to sink for each logged packet whose prefix
// matches the containd format.
//
// Returns immediately on success with an idempotent stop function that
// cancels the consumer and waits for the netlink socket to close. The stop
// function is a no-op when group == 0 or sink == nil — this matches the
// Compiler.NFLogGroup contract (0 = don't emit log clauses, no consumer
// needed). On registration failure it returns a no-op stop and an error.
//
// onErr, if non-nil, is called for each non-fatal error from the netlink
// hook (e.g., parse errors on a single packet). It should not block.
type nfLogHandle interface {
	Close() error
	RegisterWithErrorFunc(context.Context, nflog.HookFunc, nflog.ErrorFunc) error
}

var openNFLog = func(cfg *nflog.Config) (nfLogHandle, error) {
	return nflog.Open(cfg)
}

func StartNFLog(ctx context.Context, group uint16, sink RuleHitSink, onErr func(error)) (func(), error) {
	if sink == nil || group == 0 {
		return func() {}, nil
	}

	cfg := nflog.Config{
		Group:    group,
		Copymode: nflog.CopyPacket,
	}

	nf, err := openNFLog(&cfg)
	if err != nil {
		return func() {}, fmt.Errorf("nflog open group %d: %w", group, err)
	}

	nflogCtx, cancel := context.WithCancel(ctx)

	hook := func(a nflog.Attribute) int {
		if ev, ok := buildRuleHitEvent(a); ok {
			sink.Append(ev)
		}
		return 0
	}

	errFn := func(e error) int {
		if onErr != nil {
			onErr(e)
		}
		if nflogCtx.Err() != nil {
			return 1
		}
		return 0
	}

	if err := nf.RegisterWithErrorFunc(nflogCtx, hook, errFn); err != nil {
		cancel()
		_ = nf.Close()
		return func() {}, fmt.Errorf("nflog register group %d: %w", group, err)
	}

	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = nf.Close()
		})
	}
	return stop, nil
}

// buildRuleHitEvent converts an nflog Attribute into a firewall.rule.hit
// event. Returns (zero, false) if the prefix doesn't match the containd
// format — those are foreign log messages and should be ignored, not
// emitted as malformed events.
func buildRuleHitEvent(a nflog.Attribute) (events.Event, bool) {
	if a.Prefix == nil {
		return events.Event{}, false
	}
	m := rulePrefixRE.FindStringSubmatch(strings.TrimSpace(*a.Prefix))
	if m == nil {
		return events.Event{}, false
	}
	ruleID := m[1]
	action := m[2]

	ev := events.Event{
		Kind:      "firewall.rule.hit",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"ruleId": ruleID,
			"action": action,
			"via":    "nflog",
		},
	}

	// Decode the captured packet, if present, to populate addressing
	// fields. nflog can be configured to copy meta-only (no payload) by
	// the operator; skip silently in that case.
	if a.Payload != nil && len(*a.Payload) > 0 {
		if pkt, ok := decodeIPPacket(*a.Payload); ok {
			ev.SrcIP = pkt.SrcIP.String()
			ev.DstIP = pkt.DstIP.String()
			ev.SrcPort = pkt.SrcPort
			ev.DstPort = pkt.DstPort
			ev.Transport = pkt.Transport
			if pkt.Transport != "" {
				ev.Attributes["proto"] = pkt.Transport
			}
			if pkt.DstPort != 0 {
				ev.Attributes["port"] = strconv.Itoa(int(pkt.DstPort))
			}
		}
	}
	return ev, true
}
