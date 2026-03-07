// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Deprecated: use cmd/containd with "engine" subcommand instead.
package main

import (
	"context"
	"log"

	engineapp "github.com/tonylturner/containd/pkg/app/engine"
)

func main() {
	if err := engineapp.Run(context.Background(), engineapp.Options{}); err != nil {
		log.Fatalf("%v", err)
	}
}
