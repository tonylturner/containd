// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type testConn struct {
	local net.Addr
}

func (c testConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c testConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c testConn) Close() error                     { return nil }
func (c testConn) LocalAddr() net.Addr              { return c.local }
func (c testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c testConn) SetDeadline(time.Time) error      { return nil }
func (c testConn) SetReadDeadline(time.Time) error  { return nil }
func (c testConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnContextWithLocalIPAndRequestLookup(t *testing.T) {
	t.Parallel()

	ctx := connContextWithLocalIP(context.Background(), testConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443}})
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil).WithContext(ctx)
	ip := localIPFromRequest(req)
	if got := ip.String(); got != "192.0.2.10" {
		t.Fatalf("localIPFromRequest = %q, want 192.0.2.10", got)
	}
}

func TestBuildHTTPServers(t *testing.T) {
	t.Parallel()

	servers, listeners, err := buildHTTPServers(http.NewServeMux(), ":0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("buildHTTPServers error: %v", err)
	}
	if len(servers) != 2 || len(listeners) != 2 {
		t.Fatalf("unexpected server/listener counts: %d/%d", len(servers), len(listeners))
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

func TestBuildHTTPSServers(t *testing.T) {
	t.Parallel()

	servers, listeners, err := buildHTTPSServers(http.NewServeMux(), "127.0.0.1:0", "", &tls.Config{})
	if err != nil {
		t.Fatalf("buildHTTPSServers error: %v", err)
	}
	if len(servers) != 1 || len(listeners) != 1 {
		t.Fatalf("unexpected server/listener counts: %d/%d", len(servers), len(listeners))
	}
	_ = listeners[0].Close()
}

func TestIPInterfaceIndexLookupAndMgmtAccessHandler(t *testing.T) {
	t.Parallel()

	idx := newIPInterfaceIndex()
	idx.byIP["192.0.2.10"] = "eth1"
	idx.lastLoaded = time.Now()
	if got := idx.lookup(net.ParseIP("192.0.2.10")); got != "eth1" {
		t.Fatalf("lookup = %q, want eth1", got)
	}

	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{
		Name:   "wan",
		Device: "eth1",
		Access: config.InterfaceAccess{
			Mgmt:  boolPtr(false),
			HTTP:  boolPtr(false),
			HTTPS: boolPtr(false),
			SSH:   boolPtr(false),
		},
	}}
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := mgmtAccessHandler(store, idx, next)

	t.Run("denies management on disabled interface", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil)
		req = req.WithContext(connContextWithLocalIP(req.Context(), testConn{
			local: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8080},
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("allows loopback management", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil)
		req = req.WithContext(connContextWithLocalIP(req.Context(), testConn{
			local: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
	})
}

func TestMgmtAndSSHAllowedOnInterface(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Interfaces: []config.Interface{
			{
				Name:   "wan",
				Device: "eth1",
				Access: config.InterfaceAccess{
					Mgmt:  boolPtr(false),
					HTTP:  boolPtr(false),
					HTTPS: boolPtr(true),
					SSH:   boolPtr(false),
				},
			},
			{
				Name:   "lan1",
				Device: "eth0",
				Access: config.InterfaceAccess{
					Mgmt:  boolPtr(true),
					HTTP:  boolPtr(true),
					HTTPS: boolPtr(true),
					SSH:   boolPtr(true),
				},
			},
		},
	}

	if mgmtAllowedOnInterface(cfg, "eth1", false) {
		t.Fatal("expected HTTP management disabled on wan")
	}
	if mgmtAllowedOnInterface(cfg, "eth1", true) {
		t.Fatal("expected HTTPS management disabled when Mgmt=false")
	}
	if !MgmtAllowedOnInterface(cfg, "lan1", true) {
		t.Fatal("expected management allowed on lan1")
	}
	if sshAllowedOnInterface(cfg, "eth1") {
		t.Fatal("expected SSH disabled on wan")
	}
	if !SSHAllowedOnInterface(cfg, "lan1") {
		t.Fatal("expected SSH allowed on lan1")
	}
}
