// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// daemonFile is prepared and checked before any member of a render is published.
// A nil body removes a disabled service's file only after all checks succeed.
type daemonFile struct {
	path  string
	body  []byte
	check func(context.Context, string) error
	temp  string
}

func publishDaemonFiles(ctx context.Context, files ...daemonFile) error {
	defer func() {
		for _, f := range files {
			if f.temp != "" {
				_ = os.Remove(f.temp)
			}
		}
	}()
	for i := range files {
		f := &files[i]
		if f.body == nil {
			continue
		}
		var err error
		f.temp, err = stageDaemonFile(f.path, f.body, 0o644)
		if err != nil {
			return err
		}
		if f.check != nil {
			if err := f.check(ctx, f.temp); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, f := range files {
		if f.body == nil {
			if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else if err := os.Rename(f.temp, f.path); err != nil {
			return err
		}
	}
	return nil
}

func checkDaemon(ctx context.Context, binary string, args ...string) error {
	if binary == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, binary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s preflight: %w: %s", filepath.Base(binary), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func serviceConfigError(service string, err error) error {
	if err == nil {
		return nil
	}
	var fault *config.ServiceConfigError
	if errors.As(err, &fault) {
		return err
	}
	return &config.ServiceConfigError{Service: service, Err: err}
}

// The exported config entry point preserves the same structural policy for
// direct runtime callers as for config-store callers, including dormant fields.
func validateDaemonService(s config.ServicesConfig) error {
	return config.ValidateServiceConfigs(&config.Config{Services: s})
}

func validateDaemonPaths(paths ...string) error {
	for _, p := range paths {
		if err := config.ValidateClamdSocketPath(p); err != nil {
			return fmt.Errorf("daemon path must be a clean absolute ASCII path: %w", err)
		}
	}
	return nil
}

// stageDaemonFile writes an exclusively created sibling, never the active path.
func stageDaemonFile(path string, data []byte, mode os.FileMode) (string, error) {
	// Some daemons select their parser from the extension (not the contents).
	// Keep that extension last while validating an unpublished sibling.
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	f, err := os.CreateTemp(filepath.Dir(path), "."+strings.TrimSuffix(base, ext)+"-*"+ext)
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(f.Name())
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	keep = true
	return f.Name(), nil
}

// writeFileAtomic replaces path so readers see the old or new content only.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := stageDaemonFile(path, data, mode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp) }()
	return os.Rename(temp, path)
}
