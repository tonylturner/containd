// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/enginetransport"
)

var engineTransportSecret = hex.EncodeToString([]byte("public engine transport test key"))

func TestEngineTransportStartup(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", "")
	for _, enforce := range []bool{false, true} {
		for _, addr := range []string{":8081", "0.0.0.0:8081", "[::]:8081", "localhost:8081"} {
			err := Run(context.Background(), Options{Addr: addr, Combined: true, EnforceEnabled: &enforce})
			if err == nil || !strings.Contains(err.Error(), "CONTAIND_ENGINE_SECRET") {
				t.Fatalf("%s enforce=%t: %v", addr, enforce, err)
			}
		}
	}
}

// startTransportEngine exercises Run itself, including the production mux,
// listener, probes and delegated learner/AV registrations. No traffic capture,
// enforcement, service configuration or host network changes are requested.
func startTransportEngine(t *testing.T, remote bool) (string, string) {
	t.Helper()
	t.Setenv("CONTAIND_LOG_FILE", "0")
	t.Setenv("CONTAIND_LOG_SYSLOG_ADDR", "")
	t.Setenv("CONTAIND_CAPTURE_IFACES", "")
	t.Setenv("NGFW_CAPTURE_IFACES", "")
	t.Setenv("CONTAIND_DPI_MOCK", "0")
	t.Setenv("CONTAIND_EVIDENCE_DB", filepath.Join(t.TempDir(), "evidence.db"))
	t.Setenv("CONTAIND_PCAP_DIR", t.TempDir())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	listener.Close()
	addr := net.JoinHostPort("127.0.0.1", port)
	scheme := "http"
	if remote {
		addr = net.JoinHostPort("0.0.0.0", port)
		scheme = "https"
	}
	disabled := false
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Options{Addr: addr, Combined: true, EnforceEnabled: &disabled, Ready: ready}) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("engine startup: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("engine startup timeout")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("engine shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("engine shutdown timeout")
		}
	})
	return scheme + "://" + net.JoinHostPort("127.0.0.1", port), port
}

func TestEngineTLSProduction(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", engineTransportSecret)
	base, _ := startTransportEngine(t, true)
	secret, _ := enginetransport.Secret()
	identity, err := enginetransport.Derive(secret)
	if err != nil {
		t.Fatal(err)
	}
	noCert := identity.ClientTLS()
	noCert.Certificates = nil
	unauthenticated := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert}, Timeout: time.Second}
	defer unauthenticated.CloseIdleConnections()
	// Cover direct registrations, probes, delegated registrations, unknown paths,
	// method-qualified routes, subtree redirects and ServeMux path cleaning.
	for _, path := range []string{"/health", "/readyz", "/metrics", "/internal/events", "/internal/config", "/internal/pcap/upload", "/internal/pcap/analyze", "/internal/av/defs", "/internal/trust", "/internal/learn/watches", "/not-found", "/internal/learn/datasets/", "//internal/events"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
			req, _ := http.NewRequest(method, base+path, strings.NewReader(`{}`))
			if response, err := unauthenticated.Do(req); err == nil {
				response.Body.Close()
				t.Fatalf("unauthorized HTTP reached %s %s", method, path)
			}
		}
	}
	// A client that negotiates h2 must still get HTTP/1.1 only.
	config := identity.ClientTLS()
	config.NextProtos = []string{"h2", "http/1.1"}
	conn, err := tls.Dial("tcp", strings.TrimPrefix(base, "https://"), config)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatal("HTTP/2 enabled")
	}
	conn.Close()
	client := engineapi.NewHTTPClient(base)
	defer client.Client.CloseIdleConnections()
	for _, path := range []string{"/health", "/readyz", "/metrics", "/internal/events", "/internal/av/status", "/internal/learn/datasets", "/not-found"} {
		response, err := client.Client.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		want := http.StatusOK
		if path == "/not-found" {
			want = http.StatusNotFound
		}
		if response.StatusCode != want {
			t.Fatalf("%s: status %d", path, response.StatusCode)
		}
	}
	// Unauthorized learner mutation must not insert a watch.
	response, err := client.Client.Get(base + "/internal/learn/watches")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"id"`) {
		t.Fatal("unauthorized POST mutated evidence")
	}
}

func TestEngineTransportLoopback(t *testing.T) {
	for _, secret := range []string{"", "malformed and unused"} {
		t.Run(secret, func(t *testing.T) {
			t.Setenv("CONTAIND_ENGINE_SECRET", secret)
			base, _ := startTransportEngine(t, false)
			client := engineapi.NewHTTPClient(base)
			defer client.Client.CloseIdleConnections()
			if _, err := client.RuntimeHealth(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Run explicitly in the OpenSSL curl runtime; normal Go tests need no curl.
func TestEngineTLSCurlInterop(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_OPENSSL_CURL") != "1" {
		t.Skip("requires the operator OpenSSL curl runtime")
	}
	version, err := exec.Command("curl", "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "OpenSSL") {
		t.Fatalf("OpenSSL curl required: %s %v", version, err)
	}
	t.Log(string(version))
	t.Setenv("CONTAIND_ENGINE_SECRET", engineTransportSecret)
	_, port := startTransportEngine(t, true)
	dir := t.TempDir()
	if err := enginetransport.Export(dir); err != nil {
		t.Fatal(err)
	}
	common := []string{"--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "5", "--resolve", "containd-engine:" + port + ":127.0.0.1", "https://containd-engine:" + port + "/health", "--cacert", filepath.Join(dir, "server.crt")}
	authorized := append(append([]string{}, common...), "--cert", filepath.Join(dir, "client.crt"), "--key", filepath.Join(dir, "client.key"))
	if out, err := exec.Command("curl", authorized...).CombinedOutput(); err != nil {
		t.Fatalf("authorized curl: %s %v", out, err)
	}
	if out, err := exec.Command("curl", common...).CombinedOutput(); err == nil {
		t.Fatalf("curl without client cert succeeded: %s", out)
	}
}
