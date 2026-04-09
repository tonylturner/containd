// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func main() {
	logging.SetupGlobalLogger("containd")

	mode := strings.ToLower(strings.TrimSpace(os.Getenv("CONTAIND_MODE")))
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		mode = strings.ToLower(strings.TrimSpace(os.Args[1]))
	}
	// When invoked via the "configure" symlink, enter CLI mode automatically.
	if mode == "" {
		base := filepath.Base(os.Args[0])
		if base == "configure" {
			mode = "cli"
		} else {
			mode = "all"
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Handle SIGHUP for config reload (runs in background).
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			slog.Info("received SIGHUP, config reload not yet fully implemented")
		}
	}()

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
	case "cli":
		err = runCLI(ctx)
	case "healthcheck":
		err = runHealthcheck()
		if err != nil {
			os.Exit(1)
		}
		return
	default:
		err = fmt.Errorf("unknown mode %q (expected all|mgmt|engine|cli|version|healthcheck)", mode)
	}
	if err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
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

func runCLI(ctx context.Context) error {
	addr := common.Env("CONTAIND_MGMT_ADDR", "")
	if addr == "" {
		addr = ":8080"
	}
	port := addr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		port = addr[idx+1:]
	}
	baseURL := fmt.Sprintf("http://127.0.0.1:%s", port)

	token, err := cliLogin(baseURL)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	api := &cli.API{BaseURL: baseURL, Token: token}
	reg := cli.NewRegistry(nil, api)
	cmdCtx := cli.WithRole(ctx, string(cli.RoleAdmin))

	reader := bufio.NewReader(os.Stdin)
	prompt := "containd# "
	fmt.Println("containd CLI. Type 'help' for commands, 'exit' to return to shell.")
	for {
		fmt.Print(prompt)
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "exit", "quit", "logout":
			return nil
		case "shell", "bash":
			fmt.Println("Already in Linux shell. Type 'exit' to return.")
			continue
		}
		var buf strings.Builder
		if err := reg.ParseAndExecute(cmdCtx, line, &buf); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if buf.Len() > 0 {
			fmt.Print(buf.String())
			if !strings.HasSuffix(buf.String(), "\n") {
				fmt.Println()
			}
		}
	}
}

func cliLogin(baseURL string) (string, error) {
	username := common.EnvTrimmed("CONTAIND_CLI_USER", "containd")
	password := common.EnvTrimmed("CONTAIND_CLI_PASSWORD", "containd")

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login returned %d", resp.StatusCode)
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token in login response")
	}
	return result.Token, nil
}

func runAll(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- engineapp.Run(ctx, engineapp.Options{}) }()
	go func() { errCh <- mgmtapp.Run(ctx, mgmtapp.Options{Combined: true}) }()

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
