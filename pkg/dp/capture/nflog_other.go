// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package capture

import (
	"context"
	"errors"

	"github.com/tonylturner/containd/pkg/dp/events"
)

// RuleHitSink is the cross-platform interface satisfied by *events.Store
// (Append). Mirrors the linux build's definition so callers can compile.
type RuleHitSink interface {
	Append(e events.Event) events.Event
}

// StartNFLog is a no-op on non-linux platforms — nflog netlink only
// exists on Linux. Returns an explicit error if the caller passed a
// non-zero group, so the engine can surface "nflog requested but
// unavailable on this platform" rather than silently dropping events.
func StartNFLog(_ context.Context, group uint16, _ RuleHitSink, _ func(error)) error {
	if group == 0 {
		return nil
	}
	return errors.New("nflog capture is only supported on linux")
}
