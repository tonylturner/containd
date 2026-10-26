// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func trustedCATestChain(t *testing.T) string {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := &x509.Certificate{
		SerialNumber: big.NewInt(2), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	childDER, err := x509.CreateCertificate(rand.Reader, intermediate, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: childDER}))
}

func TestTrustedCAUpload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls", "trusted_ca.pem")
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TrustedCAFile = path
	store := &mockStore{cfg: cfg}
	router := gin.New()
	router.POST("/upload", trustedCAUploadHandler(store, dir))
	chain := trustedCATestChain(t)
	leaf, _ := generateTestCertPEM(t)
	post := func(body string, want int, message string) {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body)))
		if rec.Code != want || !strings.Contains(rec.Body.String(), message) {
			t.Fatalf("got %d %s; want %d containing %q", rec.Code, rec.Body.String(), want, message)
		}
	}
	encode := func(value any) string {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	post(encode(setTrustedCARequest{PEM: chain}), http.StatusOK, "updated")
	original, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(original)) != strings.TrimSpace(chain) {
		t.Fatalf("uploaded chain: %q, %v", original, err)
	}
	for _, data := range []string{"", " \n", "garbage", leaf, chain + "garbage"} {
		post(encode(setTrustedCARequest{PEM: data}), http.StatusBadRequest, "invalid PEM CA bundle")
	}
	post(`{}`, http.StatusBadRequest, "invalid PEM CA bundle")
	post(`not JSON`, http.StatusBadRequest, "invalid JSON")
	post(encode(setTrustedCARequest{PEM: chain, Clear: true}), http.StatusBadRequest, "mutually exclusive")
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("rejected upload changed bundle: %q, %v", got, err)
	}
	post(`{"clear":true}`, http.StatusOK, "updated")
	got, err = os.ReadFile(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("clear: %q, %v", got, err)
	}
}

func TestTrustedCAUploadStorageBoundary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TrustedCAFile = filepath.Join(t.TempDir(), "ca.pem")
	router := gin.New()
	router.POST("/upload", setTrustedCAHandler(&mockStore{cfg: cfg}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(`{"clear":true}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must be under /data") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}
