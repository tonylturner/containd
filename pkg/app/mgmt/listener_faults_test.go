// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"net"
	"net/http"
	"strings"
	"testing"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

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
				binds, err := buildMgmtServers(http.NewServeMux(), cfg)
				defer binds.close()
				if !reserved {
					if err == nil {
						t.Fatal("ordinary startup must still fail")
					}
					return
				}
				if err != nil || len(binds.servers) != 1 || len(binds.listeners) != 1 || len(faults.list()) != 1 {
					t.Fatalf("reserved bind: servers=%d listeners=%d err=%v faults=%v", len(binds.servers), len(binds.listeners), err, faults.list())
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
	_, err = buildMgmtServers(http.NewServeMux(), mgmtListenerConfig{
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
	reservedIP := localNonLoopbackIPv4(t)
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	cfg := mgmtListenerConfig{enableHTTP: true, httpAddr: "0.0.0.0:" + port, reservedHTTPAddr: net.JoinHostPort(reservedIP, port), optionalFault: faults.record}
	binds, err := buildMgmtServers(http.NewServeMux(), cfg)
	defer binds.close()
	listeners := binds.listeners
	if err != nil || len(listeners) != 1 || len(faults.list()) > 1 {
		t.Fatalf("exact reserved listener lost to wildcard: %v %v", err, faults.list())
	}
	// BSD can bind a wildcard alongside a more-specific socket. Linux refuses
	// it and must retain just the exact reserved address instead.
	if len(faults.list()) == 1 && listeners[0].Addr().String() != cfg.reservedHTTPAddr {
		t.Fatalf("did not isolate mandatory endpoint: %s", listeners[0].Addr())
	}
	if len(faults.list()) == 1 {
		// The occupied loopback port is not management's: the record names
		// the reserved endpoint, and the console has nothing to call.
		publishTestBinds(t, cfg, binds)
		if got := config.BoundManagementListeners().HTTP; got.Addr != cfg.reservedHTTPAddr || !got.Enabled {
			t.Fatalf("bound HTTP = %+v, want %s", got, cfg.reservedHTTPAddr)
		}
		if baseURL, _, err := httpapi.LoopbackManagementAPI(); err == nil {
			t.Fatalf("console calls %s, which management did not bind", baseURL)
		}
	}
}

// localNonLoopbackIPv4 is a live local IPv4 address outside 127/8. macOS
// does not assign all of 127/8 to lo0, unlike Linux: use a distinct local
// address instead of requiring root to add an alias.
func localNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if prefix, ok := address.(*net.IPNet); ok && prefix.IP.To4() != nil && !prefix.IP.IsLoopback() {
			return prefix.IP.String()
		}
	}
	t.Fatal("test requires a non-loopback IPv4 address")
	return ""
}
