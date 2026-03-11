// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Deprecated: use cmd/containd with "engine" subcommand instead.
package main

import (
	"context"
	"log/slog"
	"os"

	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	"github.com/tonylturner/containd/pkg/common/logging"
)

func main() {
	logging.SetupGlobalLogger("ngfw-engine")

	if err := engineapp.Run(context.Background(), engineapp.Options{}); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}
