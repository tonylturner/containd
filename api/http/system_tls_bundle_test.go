// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestTLSConcurrentUploadAndHandshakes(t *testing.T) {
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	path, keyPath := mgmttls.IdentityFilesIn(cfg, dir)
	oldCert, oldKey := generateTestCertPEM(t)
	newCert, newKey := generateTestCertPEM(t)
	if err := mgmttls.Publish(path, []byte(oldCert), []byte(oldKey)); err != nil {
		t.Fatal(err)
	}
	loader := mgmttls.NewLoader(path, keyPath)
	recordServed(t, ServedManagement{CertFile: path, KeyFile: keyPath, TLS: loader})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: loader.GetCertificate}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(oldCert))
	roots.AppendCertsFromPEM([]byte(newCert))
	router := gin.New()
	router.POST("/upload", tlsCertUploadHandler(&mockStore{cfg: cfg}, dir))
	oldPair, err := tls.X509KeyPair([]byte(oldCert), []byte(oldKey))
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := tls.X509KeyPair([]byte(newCert), []byte(newKey))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	failures := make(chan error, 4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			<-start
			for range 25 {
				conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "containd.local", RootCAs: roots})
				if err != nil {
					failures <- err
					return
				}
				leaf := conn.ConnectionState().PeerCertificates[0].Raw
				_ = conn.Close()
				if !bytes.Equal(leaf, oldPair.Certificate[0]) && !bytes.Equal(leaf, newPair.Certificate[0]) {
					t.Error("handshake received unknown identity")
					return
				}
			}
		})
	}
	close(start)
	for i := range 30 {
		cert, key := oldCert, oldKey
		if i%2 == 0 {
			cert, key = newCert, newKey
		}
		body, err := json.Marshal(setTLSCertRequest{CertPEM: cert, KeyPEM: key})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
		if rec.Code != 200 {
			t.Errorf("upload: %d %s", rec.Code, rec.Body)
		}
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	// A final synchronous rotation must reach the listener, not merely leave
	// it serving its last-good pair if the upload target ever drifts.
	body, err := json.Marshal(setTLSCertRequest{CertPEM: newCert, KeyPEM: newKey})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("final upload: %d %s", rec.Code, rec.Body)
	}
	var response struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Status != "updated" {
		t.Fatalf("listener and upload paths disagree: %s (%v)", rec.Body, err)
	}
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "containd.local", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, newPair.Certificate[0]) {
		t.Fatal("next handshake did not serve the upload at the resolved listener path")
	}
}

func TestTLSStatusAndPinKeepLastGoodExternalPair(t *testing.T) {
	cert, key := generateTestCertPEM(t)
	other, _ := sanTestCertPEM(t, "invalid-rotation", []string{"other.example"}, nil)
	dir := t.TempDir()
	c := filepath.Join(dir, "c")
	k := filepath.Join(dir, "k")
	for path, data := range map[string]string{c: cert, k: key} {
		if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	loader := mgmttls.NewLoader(c, k)
	first, err := loader.PublicLeaf()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = c
	cfg.System.Mgmt.TLSKeyFile = k
	recordServed(t, ServedManagement{CertFile: c, KeyFile: k, TLS: loader})
	if err := os.WriteFile(c, other, 0o640); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
	var got tlsInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ReloadError == "" || got.ServedCertSubject != first.Subject.String() || got.CertSubject != got.ServedCertSubject {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("status exposed key")
	}
	leaf, err := loader.PublicLeaf()
	if leaf == nil || err == nil || !bytes.Equal(leaf.Raw, first.Raw) {
		t.Fatal("pin lost last-good")
	}
}

func TestTLSPinParserAcceptsValidatedBundleOnly(t *testing.T) {
	cert, key := generateTestCertPEM(t)
	_, otherKey := generateTestCertPEM(t)
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"bundle", cert + key, true}, {"chain", cert, true}, {"mismatch", cert + otherKey, false}, {"two keys", cert + key + key, false}, {"key then cert", key + cert, false}, {"trailing text", cert + key + "garbage", false},
		{"malformed prefix", "-----BEGIN CERTIFICATE-----\nnot PEM\n" + cert + key, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bundle")
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			leaf, err := readLeafCertificate(path)
			if (err == nil) != tc.valid || tc.valid && leaf == nil {
				t.Fatalf("%v %v", leaf, err)
			}
		})
	}
}

func TestFactoryResetPreservesTLSIdentity(t *testing.T) {
	for _, managed := range []bool{true, false} {
		t.Run(map[bool]string{true: "managed", false: "external"}[managed], func(t *testing.T) {
			ctx := context.Background()
			store := stageStore(t)
			cfg, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "server.pem")
			cert, key := generateTestCertPEM(t)
			if err := mgmttls.Publish(path, []byte(cert), []byte(key)); err != nil {
				t.Fatal(err)
			}
			if managed {
				cfg.System.Mgmt.TLSCertFile = mgmttls.DefaultCertFile
				cfg.System.Mgmt.TLSKeyFile = mgmttls.DefaultKeyFile
			} else {
				cfg.System.Mgmt.TLSCertFile = path
				cfg.System.Mgmt.TLSKeyFile = path
			}
			if err := store.Save(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			us, err := users.NewSQLiteStore(filepath.Join(dir, "users.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer us.Close()
			router := gin.New()
			router.POST("/reset", factoryResetHandler(store, us, &mockEngine{}, nil))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(`{"confirm":"NUCLEAR"}`)))
			if rec.Code != 200 {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			next, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if next.System.Mgmt.TLSCertFile != cfg.System.Mgmt.TLSCertFile || next.System.Mgmt.TLSKeyFile != cfg.System.Mgmt.TLSKeyFile {
				t.Fatal("reset changed identity selection")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("reset changed TLS bytes")
			}
		})
	}
}
