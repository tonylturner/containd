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

// StartNFLog is a no-op on non-linux platforms when disabled or without a
// sink. A configured group reports that nflog is unavailable on this OS.
func StartNFLog(_ context.Context, group uint16, sink RuleHitSink, _ func(error)) (func(), error) {
	if group == 0 || sink == nil {
		return func() {}, nil
	}
	return func() {}, errors.New("nflog capture is only supported on linux")
}
