// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/peterh/liner"

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

	prompt := "containd# "
	fmt.Println("containd CLI. Type 'help' for commands, 'exit' to return to shell. Tab to complete.")

	// peterh/liner provides line editing + tab completion + history.
	// It falls back to plain line reading when stdin isn't a TTY (the
	// CLI is also used non-interactively from scripts), so the same
	// loop works in both modes.
	state := liner.NewLiner()
	defer state.Close()
	state.SetCtrlCAborts(true)

	// Completer: prefix-match against every registered command.
	// Registry.Commands() returns the list (e.g., "show running-config",
	// "set firewall rule") and the completer just filters by the
	// current line. Liner handles single-match auto-fill + multi-match
	// listing on its own.
	commands := reg.Commands()
	sort.Strings(commands)
	state.SetCompleter(func(line string) []string {
		needle := strings.ToLower(line)
		var matches []string
		for _, cmd := range commands {
			if strings.HasPrefix(cmd, needle) {
				matches = append(matches, cmd)
			}
		}
		return matches
	})

	// History across CLI sessions. Best-effort: failures (e.g., no
	// home dir, read-only fs) just disable persistence.
	historyPath := cliHistoryPath()
	if historyPath != "" {
		if f, err := os.Open(historyPath); err == nil {
			_, _ = state.ReadHistory(f)
			f.Close()
		}
		defer func() {
			if f, err := os.Create(historyPath); err == nil {
				_, _ = state.WriteHistory(f)
				f.Close()
			}
		}()
	}

	for {
		line, err := state.Prompt(prompt)
		if err != nil {
			if errors.Is(err, liner.ErrPromptAborted) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		state.AppendHistory(line)

		switch strings.ToLower(line) {
		// Both "exit"/"quit"/"logout" and "shell"/"bash" leave the
		// containd CLI. The wrapper that launched `containd cli`
		// (e.g., the SSH appliance shell or RangerDanger's in-app
		// firewall terminal) drops the operator back into a Linux
		// shell on return — so `shell` and `bash` are equivalent
		// to `exit` here, not a separate sub-shell.
		case "exit", "quit", "logout", "shell", "bash":
			return nil
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

// cliHistoryPath returns the per-user history file path or "" if
// the home directory is unavailable.
func cliHistoryPath() string {
	if v := os.Getenv("CONTAIND_CLI_HISTORY"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".containd_history")
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
