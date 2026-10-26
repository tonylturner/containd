// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestConfigApplyDistributesTrustedCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_ca.pem")
	chain := trustedCATestChain(t)
	if err := trust.WriteBundle(path, []byte(chain)); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TrustedCAFile = path
	engine := &mockEngine{}
	warnings, err := ApplyRunningConfig(context.Background(), &mockStore{cfg: cfg}, engine, nil)
	if err != nil {
		t.Fatalf("ApplyRunningConfig: %v (warnings %v)", err, warnings)
	}
	want, err := trust.LoadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(engine.trustPushes) != 1 || engine.trustPushes[0] != want || want.Empty() {
		t.Fatalf("trust pushes = %+v, want %+v", engine.trustPushes, want)
	}

	// A missing file distributes the empty bundle, clearing engine trust.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRunningConfig(context.Background(), &mockStore{cfg: cfg}, engine, nil); err != nil {
		t.Fatal(err)
	}
	if last := engine.trustPushes[len(engine.trustPushes)-1]; !last.Empty() || last.Revision != trust.NoRevision {
		t.Fatalf("missing bundle pushed %+v", last)
	}

	// Engine and storage failures surface as apply warnings.
	engine.trustErr = errors.New("engine trust unavailable")
	warnings, err = ApplyRunningConfig(context.Background(), &mockStore{cfg: cfg}, engine, nil)
	if err != nil || !containsWarning(warnings, "trust: engine trust unavailable") {
		t.Fatalf("warnings = %v, err = %v", warnings, err)
	}
	engine.trustErr = nil
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	warnings, err = ApplyRunningConfig(context.Background(), &mockStore{cfg: cfg}, engine, nil)
	if err != nil || !containsWarning(warnings, "trust: ") {
		t.Fatalf("invalid stored bundle: warnings = %v, err = %v", warnings, err)
	}
}

func containsWarning(warnings []string, part string) bool {
	for _, w := range warnings {
		if strings.Contains(w, part) {
			return true
		}
	}
	return false
}
