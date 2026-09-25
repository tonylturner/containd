// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package capture

import (
	"context"

	"github.com/tonylturner/containd/pkg/dp/events"
)

// RuleHitSink is the cross-platform interface satisfied by *events.Store
// (Append). Mirrors the linux build's definition so callers can compile.
type RuleHitSink interface {
	Append(e events.Event) events.Event
}

// StartNFLog is a no-op on non-linux platforms — nflog netlink only
// exists on Linux.
func StartNFLog(_ context.Context, _ uint16, _ RuleHitSink, _ func(error)) (func(), error) {
	return func() {}, nil
}
