// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func main() {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("CONTAIND_MODE")))
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		mode = strings.ToLower(strings.TrimSpace(os.Args[1]))
	}
	if mode == "" {
		mode = "all"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch mode {
	case "all":
		err = runAll(ctx)
	case "mgmt":
		err = mgmtapp.Run(ctx, mgmtapp.Options{})
	case "engine":
		err = engineapp.Run(ctx, engineapp.Options{})
	case "version":
		fmt.Printf("containd %s (%s)\n", config.BuildVersion, config.BuildCommit)
		return
	case "healthcheck":
		err = runHealthcheck()
		if err != nil {
			os.Exit(1)
		}
		return
	default:
		err = fmt.Errorf("unknown mode %q (expected all|mgmt|engine|version|healthcheck)", mode)
	}
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func runHealthcheck() error {
	addr := common.Env("CONTAIND_MGMT_ADDR", "")
	if addr == "" {
		addr = ":8080"
	}
	// Strip bind address, keep port.
	port := addr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		port = addr[idx+1:]
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/api/v1/health", port))
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return nil
}

func runAll(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- engineapp.Run(ctx, engineapp.Options{}) }()
	go func() { errCh <- mgmtapp.Run(ctx, mgmtapp.Options{}) }()

	// If either plane exits, cancel the other and drain both results.
	var firstErr error
	select {
	case firstErr = <-errCh:
		cancel()
	case <-ctx.Done():
		firstErr = ctx.Err()
	}
	// Wait for the second goroutine.
	if err := <-errCh; firstErr == nil {
		firstErr = err
	}
	return firstErr
}
