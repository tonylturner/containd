// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/tonylturner/containd/pkg/mp/sshserver"
)

// boundHTTP is the bound management record of an HTTP listener CLI
// sessions can call; SSH is not recorded yet.
var boundHTTP = config.ManagementListeners{HTTP: config.ManagementListener{Addr: "127.0.0.1:8080", Enabled: true}}

// sshBindTest prepares startSSH to bind addr in lab mode with HTTP recorded
// as bound management, until the test ends.
func sshBindTest(t *testing.T, addr string) users.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := users.NewSQLiteStore(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_SSH_ADDR", addr)
	t.Setenv("CONTAIND_SSH_HOST_KEY", filepath.Join(dir, "host_key"))
	t.Setenv("CONTAIND_SSH_AUTH_KEYS_DIR", filepath.Join(dir, "authorized_keys"))
	config.SetBoundManagementListeners(boundHTTP)
	t.Cleanup(func() { config.SetBoundManagementListeners(config.ManagementListeners{}) })
	return store
}

// An SSH socket that fails to bind is a listener fault reported before
// startSSH returns: SSH is off and not recorded as bound, and the bound HTTP
// listener stays recorded.
func TestSSHBindFailureIsNotRecorded(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	store := sshBindTest(t, occupied.Addr().String())
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	var reported []error
	notified := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, enabled := startSSH(ctx, zap.NewNop().Sugar(), config.DefaultConfig(), nil, store, nil, nil, func(err error) {
		faults.record(err)
		reported = append(reported, err)
	}, func(*sshserver.Server) { notified = true })
	if enabled || addr != "" {
		t.Fatalf("SSH enabled on %q with its port occupied", addr)
	}
	var opErr *net.OpError
	if len(reported) != 1 || !errors.As(reported[0], &opErr) || opErr.Op != "listen" || len(faults.list()) != 1 {
		t.Fatalf("SSH bind fault = %v, listener faults %v", reported, faults.list())
	}
	if notified {
		t.Fatal("an SSH server that did not bind was published")
	}
	if bound := config.BoundManagementListeners(); bound != boundHTTP {
		t.Fatalf("bound = %+v, want HTTP only", bound)
	}
}

// startSSH records SSH as bound at the address its socket bound, which
// accepts connections once startSSH returns.
func TestSSHRecordedOnceBound(t *testing.T) {
	store := sshBindTest(t, "127.0.0.1:0")
	var faults []error
	var published *sshserver.Server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, enabled := startSSH(ctx, zap.NewNop().Sugar(), config.DefaultConfig(), nil, store, nil, nil,
		func(err error) { faults = append(faults, err) }, func(srv *sshserver.Server) { published = srv })
	if !enabled || len(faults) != 0 || published == nil {
		t.Fatalf("SSH did not start: %q %v faults=%v published=%v", addr, enabled, faults, published != nil)
	}
	if published.Addr().String() != addr {
		t.Fatalf("startSSH returned %q, server bound %v", addr, published.Addr())
	}
	want := boundHTTP
	want.SSH = config.ManagementListener{Addr: addr, Enabled: true}
	if bound := config.BoundManagementListeners(); bound != want || bound.SSH.Port() == 0 {
		t.Fatalf("bound = %+v, want %+v", bound, want)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial the recorded SSH socket: %v", err)
	}
	_ = conn.Close()
}
