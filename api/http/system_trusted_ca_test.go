// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/trust"
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
	engine := &mockEngine{}
	router.POST("/upload", trustedCAUploadHandler(store, engine, dir))
	chain := trustedCATestChain(t)
	leaf, _ := generateTestCertPEM(t)
	post := func(body string, want int, message string) {
		t.Helper()
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body)))
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
	// The engine receives the stored content and its revision, not a path.
	if len(engine.trustPushes) != 1 || engine.trustPushes[0].PEM != string(original) || engine.trustPushes[0].Revision != trust.Revision(string(original)) {
		t.Fatalf("engine trust pushes = %+v", engine.trustPushes)
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
	if len(engine.trustPushes) != 1 {
		t.Fatalf("rejected uploads reached the engine: %+v", engine.trustPushes)
	}
	post(`{"clear":true}`, http.StatusOK, "updated")
	got, err = os.ReadFile(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("clear: %q, %v", got, err)
	}
	if last := engine.trustPushes[len(engine.trustPushes)-1]; !last.Empty() || last.Revision != trust.NoRevision {
		t.Fatalf("clear pushed %+v", last)
	}

	// A bundle the engine cannot apply is stored, and the response says so
	// with its revision and a warning instead of reporting it applied.
	engine.trustErr = errors.New("dial tcp: connection refused")
	stored := func(router *gin.Engine, body, wantRevision, wantWarning string) {
		t.Helper()
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body)))
		var got struct {
			Status   string   `json:"status"`
			Revision string   `json:"revision"`
			Warnings []string `json:"warnings"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
			t.Fatalf("stored upload: %d %s", rec.Code, rec.Body)
		}
		want := []string{"trust: " + wantWarning}
		if got.Status != "stored" || got.Revision != wantRevision || !slices.Equal(got.Warnings, want) {
			t.Fatalf("stored upload = %+v, want stored %s with warnings %q", got, wantRevision, want)
		}
		if header := rec.Header().Values("X-Containd-Warnings"); !slices.Equal(header, want) {
			t.Fatalf("X-Containd-Warnings = %q, want %q", header, want)
		}
	}
	stored(router, encode(setTrustedCARequest{PEM: chain}), trust.Revision(string(original)), "dial tcp: connection refused")
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("bundle not saved when the engine failed: %q, %v", got, err)
	}
	noEngine := gin.New()
	noEngine.POST("/upload", trustedCAUploadHandler(store, nil, dir))
	stored(noEngine, `{"clear":true}`, trust.NoRevision, "engine unavailable")

	// Only a missing config store is unavailable; nothing is stored then.
	engine.trustErr = nil
	noStore := gin.New()
	noStore.POST("/upload", trustedCAUploadHandler(nil, engine, dir))
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, noStore, rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(encode(setTrustedCARequest{PEM: chain}))))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "config store unavailable") {
		t.Fatalf("no store: %d %s", rec.Code, rec.Body)
	}
	if got, err := os.ReadFile(path); err != nil || len(got) != 0 {
		t.Fatalf("upload without a store changed the bundle: %q, %v", got, err)
	}
}

func TestTrustedCAUploadStorageBoundary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TrustedCAFile = filepath.Join(t.TempDir(), "ca.pem")
	router := gin.New()
	router.POST("/upload", setTrustedCAHandler(&mockStore{cfg: cfg}, &mockEngine{}))
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(`{"clear":true}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "must be under /data") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}
