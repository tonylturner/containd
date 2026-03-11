// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Deprecated: use cmd/containd with "mgmt" subcommand instead.
package main

import (
	"context"
	"log/slog"
	"os"

	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/common/logging"
)

func main() {
	logging.SetupGlobalLogger("ngfw-mgmt")

	if err := mgmtapp.Run(context.Background(), mgmtapp.Options{}); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}
