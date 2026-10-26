// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package capture

import (
	"context"
	"errors"
)

// StartNFLog is a no-op on non-linux platforms when disabled or without a
// sink. A configured group reports that nflog is unavailable on this OS.
func StartNFLog(_ context.Context, group uint16, sink RuleHitSink, _ func(error)) (func(), error) {
	if group == 0 || sink == nil {
		return func() {}, nil
	}
	return func() {}, errors.New("nflog capture is only supported on linux")
}
