// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package conntrack

import (
	"context"
	"fmt"
)

func List(ctx context.Context, limit int) ([]Entry, error) {
	_ = ctx
	_ = limit
	return nil, fmt.Errorf("conntrack is only available on Linux")
}
