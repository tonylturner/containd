// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Deprecated: use cmd/containd with "mgmt" subcommand instead.
package main

import (
	"context"
	"log"

	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
)

func main() {
	if err := mgmtapp.Run(context.Background(), mgmtapp.Options{}); err != nil {
		log.Fatalf("%v", err)
	}
}
