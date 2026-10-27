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
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type testConn struct {
	local net.Addr
}

func TestReservedHTTPGateSocketTupleAndSameAuth(t *testing.T) {
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "lan3", Device: "eth7", Access: config.InterfaceAccess{Mgmt: boolPtr(false), HTTP: boolPtr(false), HTTPS: boolPtr(false)}}}
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	idx := newIPInterfaceIndex()
	idx.byIP["10.99.99.2"] = "eth7"
	idx.lastLoaded = time.Now()
	reservation := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	// The ordinary downstream auth/router is still authoritative.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid" {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := mgmtAccessHandler(store, idx, reservation, next)
	for _, tc := range []struct {
		name, remote, auth string
		port               int
		tls                bool
		want               int
	}{
		{"reserved authenticated", "10.99.99.10:45100", "Bearer valid", 8080, false, 204},
		{"reserved unauthenticated", "10.99.99.10:45100", "", 8080, false, 401},
		{"other peer spoofs headers", "10.99.99.11:45100", "Bearer valid", 8080, false, 403},
		{"wrong local port", "10.99.99.10:45100", "Bearer valid", 8081, false, 403},
		{"HTTPS not reserved", "10.99.99.10:45100", "Bearer valid", 8080, true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://10.99.99.10:8080/ordinary/router", nil)
			req.RemoteAddr = tc.remote
			req.Header.Set("Authorization", tc.auth)
			req.Header.Set("X-Forwarded-For", "10.99.99.10")
			req.Header.Set("Forwarded", "for=10.99.99.10;host=10.99.99.2:8080")
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			req = req.WithContext(connContextWithLocalIP(req.Context(), testConn{local: &net.TCPAddr{IP: net.ParseIP("10.99.99.2"), Port: tc.port}}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
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

func TestBuildListenerServersHTTP(t *testing.T) {
	t.Parallel()

	var b mgmtBinds
	bound, err := b.bindListener(http.NewServeMux(), ":0", "127.0.0.1:0", nil, "", nil)
	defer b.close()
	if err != nil {
		t.Fatalf("buildHTTPServers error: %v", err)
	}
	if len(b.servers) != 2 || len(b.listeners) != 2 {
		t.Fatalf("unexpected server/listener counts: %d/%d", len(b.servers), len(b.listeners))
	}
	if bound.addr != b.listeners[0].Addr().String() || bound.loopback != b.listeners[1].Addr().String() {
		t.Fatalf("bound = %+v, want the addresses of %v and %v", bound, b.listeners[0].Addr(), b.listeners[1].Addr())
	}
}

func TestBuildListenerServersHTTPS(t *testing.T) {
	t.Parallel()

	var b mgmtBinds
	bound, err := b.bindListener(http.NewServeMux(), "127.0.0.1:0", "", &tls.Config{}, "", nil)
	defer b.close()
	if err != nil {
		t.Fatalf("buildHTTPSServers error: %v", err)
	}
	if len(b.servers) != 1 || len(b.listeners) != 1 || bound.addr != b.listeners[0].Addr().String() || bound.loopback != "" {
		t.Fatalf("unexpected binds %+v: %d/%d", bound, len(b.servers), len(b.listeners))
	}
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
	handler := mgmtAccessHandler(store, idx, nil, next)

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
