// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// listenerBuilds fails the first build with bindErr and records every
// listener configuration it is asked to build.
type listenerBuilds struct {
	t       *testing.T
	bindErr error
	failAll bool
	built   []mgmtListenerConfig
}

func (b *listenerBuilds) build(lc mgmtListenerConfig) (mgmtBinds, error) {
	b.built = append(b.built, lc)
	if len(b.built) == 1 || b.failAll {
		return mgmtBinds{}, b.bindErr
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = ln.Close() })
	return mgmtBinds{servers: []*http.Server{{}}, listeners: []net.Listener{ln}}, nil
}

// bootStores opens the management stores over a stored running config
// with the given HTTP listener, as a boot does.
func bootStores(t *testing.T, httpListen string) (mgmtStores, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	sshTestKeyPair(t, dir, "server")
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	t.Setenv("CONTAIND_TLS_CERT_FILE", filepath.Join(dir, "server.crt"))
	t.Setenv("CONTAIND_TLS_KEY_FILE", filepath.Join(dir, "server.key"))
	t.Setenv("CONTAIND_MGMT_ADDR", "")
	t.Setenv("CONTAIND_MGMT_HTTPS_ADDR", "")
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt"}}
	cfg.System.Mgmt.ListenAddr = httpListen
	cfg.System.Mgmt.HTTPListenAddr = httpListen
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stores.store.Close()
		stores.auditStore.Close()
		stores.userStore.Close()
	})
	return stores, running
}

// A stored management listener that cannot be bound does not stop
// management: it binds the default listeners and enters recovery with the
// bind failure as its boot fault.
func TestUnbindableStoredListenerEntersRecovery(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()
	stores, running := bootStores(t, "192.0.2.50:9090")
	if fault, err := config.ManagementBootFaultForStore(ctx, stores.store); err != nil || fault != "" {
		t.Fatalf("valid stored config faulted at boot: %q %v", fault, err)
	}
	listener, err := resolveMgmtListenerConfig(logger, running, nil)
	if err != nil {
		t.Fatal(err)
	}
	builds := &listenerBuilds{t: t, bindErr: errors.New("listen tcp 192.0.2.50:9090: bind: cannot assign requested address")}
	bound, err := bindManagement(logger, stores, running, nil, listener, builds.build)
	if err != nil {
		t.Fatalf("unbindable stored listener stopped management: %v", err)
	}
	if len(builds.built) != 2 || builds.built[0].httpAddr != "192.0.2.50:9090" || builds.built[1].httpAddr != ":8080" || builds.built[1].httpsAddr != ":8443" {
		t.Fatalf("built listeners %+v, want the stored then the default listeners", builds.built)
	}
	if bound.listener.httpAddr != ":8080" || bound.cfg.System.Mgmt.HTTPListenAddr != ":8080" || len(bound.binds.listeners) != 1 {
		t.Fatalf("bound = %+v", bound)
	}
	fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
	if err != nil || !strings.Contains(fault, "management listener: listen tcp 192.0.2.50:9090") {
		t.Fatalf("boot fault = %q, %v", fault, err)
	}
	if bound.event == nil || bound.event.Kind != "management.recovery.boot_fault" {
		t.Fatalf("boot event = %+v", bound.event)
	}
	// The API still shows the stored listener for diagnosis.
	stored, err := stores.store.Load(ctx)
	if err != nil || stored.System.Mgmt.HTTPListenAddr != "192.0.2.50:9090" {
		t.Fatalf("stored config changed: %v %v", stored, err)
	}
}

// Without stored listener settings to replace, or with a reservation, a
// bind failure stays fatal; so does a failure of the default listeners.
func TestListenerBindFailuresThatStayFatal(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()
	bindErr := errors.New("listen tcp :8080: bind: address already in use")

	stores, running := bootStores(t, ":8080")
	listener, err := resolveMgmtListenerConfig(logger, running, nil)
	if err != nil {
		t.Fatal(err)
	}
	builds := &listenerBuilds{t: t, bindErr: bindErr}
	if _, err := bindManagement(logger, stores, running, nil, listener, builds.build); !errors.Is(err, bindErr) || len(builds.built) != 1 {
		t.Fatalf("default listener failure = %v after %d builds, want fatal", err, len(builds.built))
	}

	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	builds = &listenerBuilds{t: t, bindErr: bindErr}
	if _, err := bindManagement(logger, stores, running, r, listener, builds.build); !errors.Is(err, bindErr) || len(builds.built) != 1 {
		t.Fatalf("reserved listener failure = %v after %d builds, want fatal", err, len(builds.built))
	}

	stores, running = bootStores(t, "192.0.2.50:9090")
	if listener, err = resolveMgmtListenerConfig(logger, running, nil); err != nil {
		t.Fatal(err)
	}
	builds = &listenerBuilds{t: t, bindErr: bindErr, failAll: true}
	if _, err := bindManagement(logger, stores, running, nil, listener, builds.build); !errors.Is(err, bindErr) || len(builds.built) != 2 {
		t.Fatalf("failing defaults = %v after %d builds, want fatal", err, len(builds.built))
	}
	if fault, err := config.ManagementBootFaultForStore(ctx, stores.store); err != nil || fault != "" {
		t.Fatalf("a fatal bind recorded boot fault %q, %v", fault, err)
	}
}
