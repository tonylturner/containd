// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// configuredBinds is the binds of lc when every enabled listener bound its
// own address and nothing else.
func configuredBinds(lc mgmtListenerConfig) mgmtBinds {
	var b mgmtBinds
	if lc.enableHTTP {
		b.http.addr = lc.httpAddr
	}
	if lc.enableHTTPS {
		b.https.addr = lc.httpsAddr
	}
	b.redirects = lc.enableHTTP && lc.enableHTTPS && lc.redirectHTTPToHTTPS
	return b
}

// publishTestBinds records b as this process's bound management until the
// test ends.
func publishTestBinds(t *testing.T, lc mgmtListenerConfig, b mgmtBinds) {
	t.Helper()
	publishBoundManagement(lc, b)
	t.Cleanup(func() {
		config.SetBoundManagementListeners(config.ManagementListeners{})
		httpapi.SetServedManagement(httpapi.ServedManagement{})
	})
}

// serveTestBinds serves the sockets b holds with their servers until the
// test ends.
func serveTestBinds(t *testing.T, b mgmtBinds) {
	t.Helper()
	errCh := make(chan error, len(b.servers))
	for i := range b.servers {
		go serveMgmtServer(b.servers[i], b.listeners[i], errCh)
	}
	t.Cleanup(func() {
		for _, srv := range b.servers {
			_ = srv.Close()
		}
	})
}

// occupiedLoopback holds 127.0.0.1 on a free port for another process and
// reports every connection it accepts.
func occupiedLoopback(t *testing.T) (net.Listener, string, <-chan struct{}) {
	t.Helper()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	accepted := make(chan struct{}, 16)
	go func() {
		for {
			c, err := occupied.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()
	_, port, _ := net.SplitHostPort(occupied.Addr().String())
	return occupied, port, accepted
}

// An optional loopback socket that fails to bind is not recorded: the
// console and SSH CLI sessions never call the port another process holds on
// 127.0.0.1, and with no other listener to call they fail with a fault.
func TestFailedLoopbackBindIsNotRecorded(t *testing.T) {
	ip := localNonLoopbackIPv4(t)
	_, port, accepted := occupiedLoopback(t)
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	lc := mgmtListenerConfig{
		enableHTTP: true, httpAddr: net.JoinHostPort(ip, port), httpLoopbackAddr: net.JoinHostPort("127.0.0.1", port),
		optionalFault: faults.record,
	}
	binds, err := buildMgmtServers(http.NewServeMux(), lc)
	defer binds.close()
	if err != nil || len(binds.listeners) != 1 || len(faults.list()) != 1 {
		t.Fatalf("bind: listeners=%d err=%v faults=%v", len(binds.listeners), err, faults.list())
	}
	publishTestBinds(t, lc, binds)
	bound := config.BoundManagementListeners()
	if bound.HTTP.Addr != lc.httpAddr || !bound.HTTP.Enabled || bound.HTTPS.Enabled || bound.SSH.Enabled {
		t.Fatalf("bound = %+v, want HTTP on %s only", bound, lc.httpAddr)
	}
	baseURL, _, err := httpapi.LoopbackManagementAPI()
	if err == nil || err.Error() != "no bound management HTTP or HTTPS listener accepts connections on 127.0.0.1" {
		t.Fatalf("LoopbackManagementAPI = %q, %v", baseURL, err)
	}
	var sshFaults []error
	t.Setenv("CONTAIND_SSH_ADDR", "127.0.0.1:0")
	if addr, enabled := startSSH(t.Context(), zap.NewNop().Sugar(), config.DefaultConfig(), nil, nil, nil, nil, func(err error) { sshFaults = append(sshFaults, err) }); enabled {
		t.Fatalf("SSH started on %s without a loopback listener to call", addr)
	}
	if len(sshFaults) != 1 || !strings.Contains(sshFaults[0].Error(), "accepts connections on 127.0.0.1") {
		t.Fatalf("SSH faults = %v", sshFaults)
	}
	select {
	case <-accepted:
		t.Fatal("the occupied loopback port was called")
	default:
	}
}

// With its loopback socket bound, the listener is called there, end to end
// through the bound server.
func TestBoundLoopbackSocketIsCalled(t *testing.T) {
	ip := localNonLoopbackIPv4(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	lc := mgmtListenerConfig{
		enableHTTP: true, httpAddr: net.JoinHostPort(ip, port), httpLoopbackAddr: net.JoinHostPort("127.0.0.1", port),
		optionalFault: faults.record,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "management") })
	binds, err := buildMgmtServers(mux, lc)
	defer binds.close()
	if err != nil || len(binds.listeners) != 2 || len(faults.list()) != 0 {
		t.Fatalf("bind: listeners=%d err=%v faults=%v", len(binds.listeners), err, faults.list())
	}
	serveTestBinds(t, binds)
	publishTestBinds(t, lc, binds)
	if bound := config.BoundManagementListeners(); bound.HTTP.Addr != lc.httpAddr || bound.SSH != (config.ManagementListener{}) {
		t.Fatalf("bound = %+v", bound)
	}
	baseURL, client, err := httpapi.LoopbackManagementAPI()
	if err != nil || baseURL != "http://127.0.0.1:"+port {
		t.Fatalf("LoopbackManagementAPI = %q, %v", baseURL, err)
	}
	resp, err := client.Get(baseURL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "management" {
		t.Fatalf("health = %q, %v", body, err)
	}
}

// An HTTPS listener that fails to bind is not recorded: no served
// certificate, and HTTP does not redirect to it. The console calls HTTP.
func TestFailedHTTPSBindIsNotRecorded(t *testing.T) {
	occupied, _, accepted := occupiedLoopback(t)
	dir := t.TempDir()
	cert, key, _ := sshTestKeyPair(t, dir, "server")
	faults := &bootListenerFaults{logger: zap.NewNop().Sugar()}
	lc := mgmtListenerConfig{
		enableHTTP: true, httpAddr: "127.0.0.1:0",
		enableHTTPS: true, httpsAddr: occupied.Addr().String(), redirectHTTPToHTTPS: true,
		tlsCert: cert, tlsKey: key, tlsLoader: newCertReloader(cert, key),
		optionalFault: faults.record,
	}
	binds, err := buildMgmtServers(http.NewServeMux(), lc)
	defer binds.close()
	if err != nil || len(binds.listeners) != 1 || len(faults.list()) != 1 || binds.redirects {
		t.Fatalf("bind: listeners=%d err=%v faults=%v redirects=%v", len(binds.listeners), err, faults.list(), binds.redirects)
	}
	publishTestBinds(t, lc, binds)
	if bound := config.BoundManagementListeners(); bound.HTTPS.Enabled || !bound.HTTP.Enabled || bound.SSH != (config.ManagementListener{}) {
		t.Fatalf("bound = %+v", bound)
	}
	if served := lc.servedManagement(binds); served != (httpapi.ServedManagement{}) {
		t.Fatalf("served = %+v", served)
	}
	baseURL, _, err := httpapi.LoopbackManagementAPI()
	if err != nil || baseURL != "http://"+binds.listeners[0].Addr().String() {
		t.Fatalf("LoopbackManagementAPI = %q, %v", baseURL, err)
	}
	select {
	case <-accepted:
		t.Fatal("the occupied HTTPS port was called")
	default:
	}
}

// HTTP redirects to HTTPS only when HTTPS bound its own socket.
func TestHTTPRedirectFollowsHTTPSBind(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := sshTestKeyPair(t, dir, "server")
	lc := mgmtListenerConfig{
		enableHTTP: true, httpAddr: "127.0.0.1:0",
		enableHTTPS: true, httpsAddr: "127.0.0.1:0", redirectHTTPToHTTPS: true,
		tlsCert: cert, tlsKey: key, tlsLoader: newCertReloader(cert, key),
	}
	binds, err := buildMgmtServers(http.NewServeMux(), lc)
	defer binds.close()
	if err != nil || !binds.redirects {
		t.Fatalf("redirects = %v, %v", binds.redirects, err)
	}
	served := lc.servedManagement(binds)
	if !served.HTTPRedirects || served.CertFile != lc.tlsCert || served.KeyFile != lc.tlsKey {
		t.Fatalf("served = %+v", served)
	}
}
