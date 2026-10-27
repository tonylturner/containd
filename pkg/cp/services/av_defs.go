// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const (
	// MaxAVDefinitionBytes bounds one uploaded custom signature database.
	MaxAVDefinitionBytes = 64 << 20
	// customDefPrefix marks custom databases activated in DatabaseDir, so
	// they never collide with FreshClam's official databases.
	customDefPrefix = "containd-custom-"
	defValidateTime = 2 * time.Minute
)

// customDefExtensions are the ClamAV database formats clamd loads.
var customDefExtensions = []string{
	".cat", ".cbc", ".cdb", ".cfg", ".crb", ".fp", ".ftm", ".gdb", ".hdb", ".hdu",
	".hsb", ".hsu", ".idb", ".ign", ".ign2", ".imp", ".ldb", ".ldu", ".mdb", ".mdu",
	".msb", ".msu", ".ndb", ".ndu", ".pdb", ".pwdb", ".sfp", ".wdb", ".yar", ".yara",
}

// AVDefinition is one stored custom signature database.
type AVDefinition struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	// Active reports that a running clamd is loading the database.
	Active bool `json:"active"`
}

// AVDefinitionList is the engine-local custom definition inventory.
type AVDefinitionList struct {
	Path        string         `json:"path"`
	Files       []string       `json:"files"`
	Definitions []AVDefinition `json:"definitions"`
}

// ValidateDefinitionName accepts a plain file name with a ClamAV database
// extension.
func ValidateDefinitionName(name string) error {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") ||
		strings.ContainsFunc(name, func(r rune) bool {
			return !(r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
		}) {
		return fmt.Errorf("%w: definition name %q must be a plain file name of letters, digits, '.', '-' or '_'", ErrAVInvalid, name)
	}
	if !slices.Contains(customDefExtensions, strings.ToLower(filepath.Ext(name))) {
		return fmt.Errorf("%w: %q is not a ClamAV signature database type", ErrAVInvalid, name)
	}
	return nil
}

// ListDefinitions returns the stored custom databases.
func (m *AVManager) ListDefinitions() (AVDefinitionList, error) {
	cfg := m.Current()
	m.mu.Lock()
	loading := cfg.Enabled && avMode(cfg) == "clamav" && m.clamd.running()
	m.mu.Unlock()
	dir := customDefsPath(cfg)
	out := AVDefinitionList{Path: dir, Files: []string{}, Definitions: []AVDefinition{}}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || ValidateDefinitionName(e.Name()) != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		_, activeErr := os.Stat(filepath.Join(m.opts.DatabaseDir, customDefPrefix+e.Name()))
		out.Files = append(out.Files, e.Name())
		out.Definitions = append(out.Definitions, AVDefinition{
			Name:     e.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().UTC(),
			Active:   loading && activeErr == nil,
		})
	}
	return out, nil
}

// UploadDefinition validates and stores a custom database read from r, then
// activates it and reloads a running clamd. It waits for clamd's proof of
// the activation only until ctx ends; the activation itself continues.
func (m *AVManager) UploadDefinition(ctx context.Context, name string, r io.Reader) (AVDefinition, error) {
	def, err := m.uploadDefinitionLocked(ctx, name, r)
	if err != nil {
		return AVDefinition{}, err
	}
	if err := m.awaitReload(ctx); err != nil {
		return AVDefinition{}, err
	}
	return def, nil
}

func (m *AVManager) uploadDefinitionLocked(ctx context.Context, name string, r io.Reader) (AVDefinition, error) {
	if err := ValidateDefinitionName(name); err != nil {
		return AVDefinition{}, err
	}
	if err := m.lock(ctx); err != nil {
		return AVDefinition{}, err
	}
	defer m.unlock()
	cfg := m.Current()
	dir := customDefsPath(cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return AVDefinition{}, err
	}
	// Keep the database extension: clamd and clamscan select the parser by it.
	tmp, err := os.CreateTemp(dir, ".upload-*"+filepath.Ext(name))
	if err != nil {
		return AVDefinition{}, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	n, err := io.Copy(tmp, io.LimitReader(r, MaxAVDefinitionBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return AVDefinition{}, err
	}
	if n > MaxAVDefinitionBytes {
		return AVDefinition{}, fmt.Errorf("%w: definition exceeds %d bytes", ErrAVInvalid, MaxAVDefinitionBytes)
	}
	if n == 0 {
		return AVDefinition{}, fmt.Errorf("%w: definition is empty", ErrAVInvalid)
	}
	if err := m.validateDef(ctx, tmpName); err != nil {
		return AVDefinition{}, err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return AVDefinition{}, err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return AVDefinition{}, err
	}
	active, err := m.activateDefinitions(ctx, cfg)
	if err != nil {
		return AVDefinition{}, err
	}
	m.emit("service.av.definition_uploaded", map[string]any{"file": name, "active": active})
	return AVDefinition{Name: name, Size: n, Modified: time.Now().UTC(), Active: active}, nil
}

// DeleteDefinition removes a custom database and reloads a running clamd,
// waiting for clamd's proof of the activation only until ctx ends.
func (m *AVManager) DeleteDefinition(ctx context.Context, name string) error {
	if err := m.deleteDefinitionLocked(ctx, name); err != nil {
		return err
	}
	return m.awaitReload(ctx)
}

func (m *AVManager) deleteDefinitionLocked(ctx context.Context, name string) error {
	if err := ValidateDefinitionName(name); err != nil {
		return err
	}
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.unlock()
	cfg := m.Current()
	if err := os.Remove(filepath.Join(customDefsPath(cfg), name)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: definition %q not found", ErrAVInvalid, name)
		}
		return err
	}
	if _, err := m.activateDefinitions(ctx, cfg); err != nil {
		return err
	}
	m.emit("service.av.definition_deleted", map[string]any{"file": name})
	return nil
}

// activateDefinitions installs the stored databases where clamd loads them
// and reloads clamd, starting it if it had exited. It reports whether clamd
// is loading them.
// Callers hold m.op.
func (m *AVManager) activateDefinitions(ctx context.Context, cfg config.AVConfig) (bool, error) {
	if err := m.syncCustomDefs(cfg); err != nil {
		return false, fmt.Errorf("activate custom definitions: %w", err)
	}
	if !cfg.Enabled || avMode(cfg) != "clamav" {
		return false, nil
	}
	if err := m.reloadClamd(ctx, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// syncCustomDefs makes the prefixed databases in DatabaseDir match the
// stored custom databases exactly.
func (m *AVManager) syncCustomDefs(cfg config.AVConfig) error {
	want := map[string][]byte{}
	entries, err := os.ReadDir(customDefsPath(cfg))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || ValidateDefinitionName(e.Name()) != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(customDefsPath(cfg), e.Name()))
		if err != nil {
			return err
		}
		want[customDefPrefix+e.Name()] = data
	}
	installed, err := os.ReadDir(m.opts.DatabaseDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range installed {
		if !strings.HasPrefix(e.Name(), customDefPrefix) {
			continue
		}
		if _, keep := want[e.Name()]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(m.opts.DatabaseDir, e.Name())); err != nil {
			return err
		}
	}
	if len(want) == 0 {
		return nil
	}
	if err := os.MkdirAll(m.opts.DatabaseDir, 0o755); err != nil {
		return err
	}
	for name, data := range want {
		dst := filepath.Join(m.opts.DatabaseDir, name)
		if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, data) {
			continue
		}
		if err := writeFileAtomic(dst, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// clamscanValidate loads only the candidate database with clamscan, which
// rejects malformed signatures before clamd ever sees them.
func (m *AVManager) clamscanValidate(ctx context.Context, path string) error {
	if m.opts.ClamscanPath == "" {
		return errors.New("clamscan is not installed in this engine image; definitions cannot be validated")
	}
	ctx, cancel := context.WithTimeout(ctx, defValidateTime)
	defer cancel()
	probe, err := os.CreateTemp("", "containd-defcheck-*")
	if err != nil {
		return err
	}
	_ = probe.Close()
	defer func() { _ = os.Remove(probe.Name()) }()
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, m.opts.ClamscanPath, "--no-summary", "--database="+path, probe.Name())
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	// Status 1 means a signature matched the empty probe file, which still
	// proves the database loaded.
	if err == nil || errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("validate definition: %w", ctx.Err())
	}
	return fmt.Errorf("%w: clamscan rejected the definition: %s", ErrAVInvalid, strings.TrimSpace(string(out)))
}
