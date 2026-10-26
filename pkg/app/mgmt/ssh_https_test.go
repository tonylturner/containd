// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// sshTestKeyPair writes a self-signed management certificate for localhost
// and 127.0.0.1 under dir and loads it.
func sshTestKeyPair(t *testing.T, dir, name string) (string, string, *tls.Certificate) {
	t.Helper()
	certFile, keyFile, err := ensureSelfSignedTLSFiles(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, &pair
}

// sshTestAddr is a loopback address no listener holds at the moment.
func sshTestAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func sshTestExec(t *testing.T, addr, command string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User: "containd", Auth: []ssh.AuthMethod{ssh.Password("containd")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // local ephemeral test server
			Timeout:         3 * time.Second,
		})
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("dial SSH: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		defer client.Close()
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		// The SSH CLI ends an exec request without an exit status.
		out, err := session.Output(command)
		var missing *ssh.ExitMissingError
		if err != nil && !errors.As(err, &missing) {
			t.Fatalf("%s: %v: %s", command, err, out)
		}
		return string(out)
	}
}

// With HTTP off and HTTPS on, SSH CLI sessions call the bound HTTPS
// listener and trust only the certificate file it serves, which can differ
// from the saved setting and the environment.
func TestSSHCallsHTTPSOnlyManagement(t *testing.T) {
	dir := t.TempDir()
	servedCert, servedKey, served := sshTestKeyPair(t, dir, "served")
	_, _, other := sshTestKeyPair(t, dir, "other")
	var presented atomic.Pointer[tls.Certificate]
	presented.Store(served)
	type call struct{ path, connection, auth string }
	calls := make(chan call, 4)
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		calls <- call{r.URL.Path, r.Header.Get("X-Containd-SSH-Connection"), r.Header.Get("Authorization")}
		_, _ = io.WriteString(w, `{"status":"pinned-https"}`)
	}))
	api.TLS = &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return presented.Load(), nil },
	}
	api.Config.ErrorLog = log.New(io.Discard, "", 0)
	api.StartTLS()
	defer api.Close()

	config.SetBoundManagementListeners(config.ManagementListeners{HTTPS: config.ManagementListener{Addr: api.Listener.Addr().String(), Enabled: true}})
	httpapi.SetServedManagement(httpapi.ServedManagement{CertFile: servedCert, KeyFile: servedKey})
	t.Cleanup(func() {
		config.SetBoundManagementListeners(config.ManagementListeners{})
		httpapi.SetServedManagement(httpapi.ServedManagement{})
	})

	userStore, err := users.NewSQLiteStore(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer userStore.Close()
	if err := userStore.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	sshAddr := sshTestAddr(t)
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	t.Setenv("CONTAIND_SSH_ADDR", sshAddr)
	t.Setenv("CONTAIND_SSH_HOST_KEY", filepath.Join(dir, "host_key"))
	t.Setenv("CONTAIND_SSH_AUTH_KEYS_DIR", filepath.Join(dir, "authorized_keys"))
	t.Setenv("CONTAIND_TLS_CERT_FILE", filepath.Join(dir, "other.crt"))
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = filepath.Join(dir, "other.crt")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var faults []error
	if addr, enabled := startSSH(ctx, zap.NewNop().Sugar(), cfg, nil, userStore, nil, nil, func(err error) { faults = append(faults, err) }); !enabled || addr != sshAddr {
		t.Fatalf("SSH did not start with HTTPS only: %q %v %v", addr, enabled, faults)
	}

	out := sshTestExec(t, sshAddr, "show health")
	if !strings.Contains(out, "pinned-https") {
		t.Fatalf("show health over HTTPS: %q", out)
	}
	select {
	case got := <-calls:
		if got.path != "/api/v1/health" || got.connection == "" || got.auth != "Bearer lab" {
			t.Fatalf("API call = %+v", got)
		}
	default:
		t.Fatal("no API call recorded")
	}

	// A listener presenting another certificate is refused before the
	// bearer token is sent.
	presented.Store(other)
	if out := sshTestExec(t, sshAddr, "show health"); !strings.Contains(out, "tls: failed to verify certificate") {
		t.Fatalf("wrong certificate accepted: %q", out)
	}
	select {
	case got := <-calls:
		t.Fatalf("API reached through a wrong certificate: %+v", got)
	default:
	}
}

// With no listener for CLI sessions to call, SSH stays off with a fault
// that says why.
func TestSSHStaysOffWithoutManagementAPI(t *testing.T) {
	config.SetBoundManagementListeners(config.ManagementListeners{})
	httpapi.SetServedManagement(httpapi.ServedManagement{})
	t.Setenv("CONTAIND_SSH_ADDR", "127.0.0.1:0")
	var faults []error
	sshAddr, enabled := startSSH(context.Background(), zap.NewNop().Sugar(), config.DefaultConfig(), nil, nil, nil, nil,
		func(err error) { faults = append(faults, err) })
	if enabled || sshAddr != "" {
		t.Fatalf("SSH started on %q without a management API to call", sshAddr)
	}
	if len(faults) != 1 || faults[0].Error() != "ssh disabled: CLI sessions have no management API to call: no management HTTP or HTTPS listener bound" {
		t.Fatalf("faults = %v", faults)
	}
}

// The bound record claims SSH whenever its CLI sessions have a listener to
// call on loopback; the served certificate is the bound HTTPS listener's.
func TestServedListenersRecordSSH(t *testing.T) {
	lc := mgmtListenerConfig{sshAddr: ":2222", tlsCert: "/c", tlsKey: "/k"}
	for _, tc := range []struct {
		name        string
		http, https boundListener
		ssh, cert   bool
	}{
		{name: "HTTP", http: boundListener{addr: "[::]:8080"}, ssh: true},
		{name: "HTTPS", https: boundListener{addr: "[::]:8443"}, ssh: true, cert: true},
		{name: "HTTP with a loopback socket", http: boundListener{addr: "10.10.10.10:8080", loopback: "127.0.0.1:8080"}, ssh: true},
		{name: "HTTP not on loopback", http: boundListener{addr: "10.10.10.10:8080"}},
		{name: "HTTPS loopback socket only", https: boundListener{loopback: "127.0.0.1:8443"}, ssh: true, cert: true},
		{name: "none"},
	} {
		b := mgmtBinds{http: tc.http, https: tc.https}
		served := lc.servedManagement(b)
		if got := lc.served(b, served).SSH.Enabled; got != tc.ssh {
			t.Errorf("%s: SSH recorded %v", tc.name, got)
		}
		if (served.CertFile == "/c" && served.KeyFile == "/k") != tc.cert {
			t.Errorf("%s: served = %+v", tc.name, served)
		}
	}
}
