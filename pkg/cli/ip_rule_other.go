// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package cli

import (
	"context"
	"fmt"
	"io"
)

func showIPRule() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return fmt.Errorf("show ip rule is only supported on Linux (run inside the containd container/appliance)")
	}
}
