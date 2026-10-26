// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	"go.uber.org/zap"
)

func TestSSHListenerFailureIsVisible(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	dir := t.TempDir()
	store, err := users.NewSQLiteStore(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_SSH_ADDR", occupied.Addr().String())
	t.Setenv("CONTAIND_SSH_HOST_KEY", filepath.Join(dir, "host_key"))
	t.Setenv("CONTAIND_SSH_AUTH_KEYS_DIR", filepath.Join(dir, "authorized_keys"))
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	reported := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// CLI sessions have a listener to call; SSH itself cannot bind.
	config.SetBoundManagementListeners(config.ManagementListeners{HTTP: config.ManagementListener{Addr: "127.0.0.1:8080", Enabled: true}})
	t.Cleanup(func() { config.SetBoundManagementListeners(config.ManagementListeners{}) })
	startSSH(ctx, zap.NewNop().Sugar(), config.DefaultConfig(), nil, store, nil, nil, func(err error) {
		faults.record(err)
		reported <- err
	})
	select {
	case err := <-reported:
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "listen" || len(faults.list()) != 1 {
			t.Fatalf("SSH did not report its bind fault: %v %v", err, faults.list())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH bind failure not reported")
	}
}

func TestOptionalListenerFailures(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		for _, kind := range []string{"https", "loopback"} {
			t.Run(kind+map[bool]string{false: "/ordinary", true: "/reserved"}[reserved], func(t *testing.T) {
				occupied, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
				faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
				cfg := mgmtListenerConfig{enableHTTP: true, httpAddr: "127.0.0.1:0"}
				if reserved {
					cfg.optionalFault = faults.record
				}
				if kind == "https" {
					cfg.enableHTTPS = true
					cfg.httpsAddr = occupied.Addr().String()
				} else {
					cfg.httpLoopbackAddr = occupied.Addr().String()
				}
				servers, listeners, err := buildMgmtServers(http.NewServeMux(), cfg)
				for _, listener := range listeners {
					defer listener.Close()
				}
				if !reserved {
					if err == nil {
						t.Fatal("ordinary startup must still fail")
					}
					return
				}
				if err != nil || len(servers) != 1 || len(listeners) != 1 || len(faults.list()) != 1 {
					t.Fatalf("reserved bind: servers=%d listeners=%d err=%v faults=%v", len(servers), len(listeners), err, faults.list())
				}
				if !strings.Contains(faults.list()[0], occupied.Addr().String()) {
					t.Fatal("fault does not identify failed listener")
				}
			})
		}
	}
}

func TestReservedListenerMandatory(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	_, _, err = buildMgmtServers(http.NewServeMux(), mgmtListenerConfig{
		enableHTTP: true, httpAddr: occupied.Addr().String(), reservedHTTPAddr: occupied.Addr().String(), optionalFault: faults.record,
	})
	if err == nil {
		t.Fatal("reserved endpoint bind must be mandatory")
	}
}

func TestReservedWildcardCollisionKeepsExactEndpoint(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	_, port, _ := net.SplitHostPort(occupied.Addr().String())
	// macOS does not assign all of 127/8 to lo0, unlike Linux. Use a live
	// distinct local IPv4 address instead of requiring root to add an alias.
	reservedIP := ""
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if prefix, ok := address.(*net.IPNet); ok && prefix.IP.To4() != nil && !prefix.IP.IsLoopback() {
			reservedIP = prefix.IP.String()
			break
		}
	}
	if reservedIP == "" {
		t.Fatal("wildcard collision test requires a non-loopback IPv4 address")
	}
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	cfg := mgmtListenerConfig{enableHTTP: true, httpAddr: "0.0.0.0:" + port, reservedHTTPAddr: net.JoinHostPort(reservedIP, port), optionalFault: faults.record}
	_, listeners, err := buildMgmtServers(http.NewServeMux(), cfg)
	for _, listener := range listeners {
		defer listener.Close()
	}
	if err != nil || len(listeners) != 1 || len(faults.list()) > 1 {
		t.Fatalf("exact reserved listener lost to wildcard: %v %v", err, faults.list())
	}
	// BSD can bind a wildcard alongside a more-specific socket. Linux refuses
	// it and must retain just the exact reserved address instead.
	if len(faults.list()) == 1 && listeners[0].Addr().String() != cfg.reservedHTTPAddr {
		t.Fatalf("did not isolate mandatory endpoint: %s", listeners[0].Addr())
	}
}
