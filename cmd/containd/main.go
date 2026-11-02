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
	"github.com/tonylturner/containd/pkg/common/enginetransport"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
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

	var reservation *mgmtpath.Reservation
	if mode == "all" || mode == "mgmt" || mode == "engine" {
		var err error
		reservation, err = mgmtpath.Load()
		if err != nil {
			slog.Error("fatal management reservation error", "error", err)
			os.Exit(1)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Handle SIGHUP for config reload (runs in background).
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)
	reloads := make(chan struct{}, 1)
	go handleReloadSignals(ctx, mode, sighupCh, reloads)

	var err error
	switch mode {
	case "all":
		err = runAll(ctx, reservation, reloads)
	case "mgmt":
		err = mgmtapp.Run(ctx, mgmtapp.Options{Reservation: reservation, Reload: reloads})
	case "engine":
		err = engineapp.Run(ctx, engineapp.Options{Reservation: reservation})
	case "enginecredentials":
		args := os.Args[1:]
		if len(args) > 0 {
			args = args[1:]
		}
		err = runEngineCredentials(args)
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
		err = fmt.Errorf("unknown mode %q (expected all|mgmt|engine|cli|version|healthcheck|enginecredentials)", mode)
	}
	if err != nil {
		if exitCode(ctx, err) == 0 {
			slog.Info("shutdown complete", "reason", err)
			return
		}
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

// runHealthcheck asks the management this container runs for its health,
// through the listener its runtime record names.
func runHealthcheck() error {
	baseURL, client, err := mgmtapp.LocalManagementAPI()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
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
	api, err := cliAPI(ctx)
	if err != nil {
		return err
	}
	reg := cli.NewRegistry(nil, api)
	cmdCtx := cli.WithRole(ctx, string(cli.RoleAdmin))

	entry, role := api.SessionEntry(ctx)
	fmt.Println(entry)
	fmt.Println("exit ends this CLI process and returns to its caller. For guided setup, use the SSH wizard. Tab to complete; help lists commands.")
	defer fmt.Println(cli.SessionExit)
	prompt := "containd(config?)# "

	// peterh/liner provides line editing + tab completion + history.
	// It falls back to plain line reading when stdin isn't a TTY (the
	// CLI is also used non-interactively from scripts), so the same
	// loop works in both modes.
	_, terminalErr := liner.TerminalMode()
	interactive := terminalErr == nil
	state := liner.NewLiner()
	defer state.Close()
	state.SetCtrlCAborts(true)
	cmdCtx = cliSecretContext(cmdCtx, interactive, state.PasswordPrompt)

	// Completer: prefix-match against every registered command.
	// Registry.Commands() returns the list (e.g., "show running-config",
	// "set firewall rule") and the completer just filters by the
	// current line. Liner handles single-match auto-fill + multi-match
	// listing on its own.
	commands := append(reg.Commands(), "configure", "exit", "quit", "logout", "help")
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

	statusPoller := cli.NewSessionStatusPoller(ctx, api)
	defer statusPoller.Close()
	return runCLILoop(prompt, func(string) (string, error) {
		status := statusPoller.Snapshot()
		fmt.Println(status.String())
		return state.Prompt(status.Prompt(role))
	}, state.AppendHistory, func(line string, buf *strings.Builder) error {
		statusPoller.SyncToken(api)
		defer statusPoller.Refresh(api)
		if output, handled := cli.SessionConfigure(line); handled {
			fmt.Fprintln(buf, output)
			return nil
		}
		if strings.EqualFold(line, "help") {
			fmt.Fprintln(buf, "Session controls: configure names this CLI; exit / quit / logout end this CLI process. Use the SSH wizard for guided setup.")
		}
		return cli.SessionCommandError(line, reg.ParseAndExecute(cmdCtx, line, buf))
	}, interactive, os.Stdout, os.Stderr)
}

var errCLISessionCommandFailed = errors.New("one or more CLI commands failed")

func runCLILoop(
	prompt string,
	readLine func(string) (string, error),
	appendHistory func(string),
	execute func(string, *strings.Builder) error,
	interactive bool,
	stdout, stderr io.Writer,
) error {
	failed := false
	sessionResult := func() error {
		if !interactive && failed {
			return errCLISessionCommandFailed
		}
		return nil
	}

	for {
		line, err := readLine(prompt)
		if err != nil {
			if errors.Is(err, liner.ErrPromptAborted) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return sessionResult()
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		appendHistory(line)

		switch strings.ToLower(line) {
		case "exit", "quit", "logout":
			return sessionResult()
		}
		var buf strings.Builder
		if err := execute(line, &buf); err != nil {
			failed = true
			fmt.Fprintln(stderr, err)
		}
		if buf.Len() > 0 {
			fmt.Fprint(stdout, buf.String())
			if !strings.HasSuffix(buf.String(), "\n") {
				fmt.Fprintln(stdout)
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

// cliAPI connects the CLI to management. In a Linux shell opened over SSH
// it acts as that SSH login. Elsewhere it calls the listener management's
// runtime record names and logs in as CONTAIND_CLI_USER with
// CONTAIND_CLI_PASSWORD.
func cliAPI(ctx context.Context) (*cli.API, error) {
	if socket := os.Getenv(cli.EnvSSHAPISocket); socket != "" {
		api, err := cli.ConnectSSHSession(ctx, socket)
		if err != nil {
			return nil, fmt.Errorf("SSH login unavailable: %w", err)
		}
		return api, nil
	}
	baseURL, client, err := mgmtapp.LocalManagementAPI()
	if err != nil {
		return nil, err
	}
	token, err := cliLogin(ctx, baseURL, client)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	return &cli.API{BaseURL: baseURL, Token: token, Client: client}, nil
}

// cliLogin logs in through client, which calls only the listener baseURL
// names and follows no redirects.
func cliLogin(ctx context.Context, baseURL string, client *http.Client) (string, error) {
	username := common.EnvTrimmed("CONTAIND_CLI_USER", "containd")
	password := common.EnvTrimmed("CONTAIND_CLI_PASSWORD", "containd")

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login returned %d", resp.StatusCode)
	}
	var result struct {
		Token       string `json:"token"`
		MFARequired bool   `json:"mfaRequired"`
		User        struct {
			MustChangePassword bool `json:"mustChangePassword"`
			MFARequired        bool `json:"mfaRequired"`
			MFAEnabled         bool `json:"mfaEnabled"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.User.MustChangePassword {
		return "", errors.New("account requires a password change; sign in through the web UI or SSH to change it before using direct CLI login")
	}
	if result.MFARequired {
		return "", errors.New("account requires MFA; use the web console or sign in through SSH instead of direct CLI login")
	}
	if result.User.MFARequired && !result.User.MFAEnabled {
		return "", errors.New("account requires MFA enrollment; complete setup in the web UI before using direct CLI login")
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token in login response")
	}
	return result.Token, nil
}

func runAll(ctx context.Context, reservation *mgmtpath.Reservation, reloads <-chan struct{}) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	var ready chan struct{}
	if reservation != nil {
		ready = make(chan struct{})
	}
	go func() {
		errCh <- engineapp.Run(ctx, engineapp.Options{Combined: true, Reservation: reservation, Ready: ready})
	}()
	if ready != nil {
		select {
		case <-ready:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	go func() {
		errCh <- mgmtapp.Run(ctx, mgmtapp.Options{Combined: true, Reservation: reservation, Reload: reloads})
	}()

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

func runEngineCredentials(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: containd enginecredentials DIRECTORY (existing directory; files must not exist)")
	}
	return enginetransport.Export(args[0])
}
