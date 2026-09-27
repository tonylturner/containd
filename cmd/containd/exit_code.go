// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	"context"
	"errors"
)

func exitCode(ctx context.Context, err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return 0
	}
	return 1
}
