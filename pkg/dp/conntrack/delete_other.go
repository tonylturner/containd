// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package conntrack

import (
	"context"
	"fmt"
)

func Delete(ctx context.Context, req DeleteRequest) error {
	_ = ctx
	_ = req
	return fmt.Errorf("conntrack delete is only available on Linux")
}

