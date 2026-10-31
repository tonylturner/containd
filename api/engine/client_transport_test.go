// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/common/enginetransport"
	"github.com/tonylturner/containd/pkg/cp/config"
)

var transportSecret = hex.EncodeToString([]byte("public engine transport test key"))
var rotatedSecret = hex.EncodeToString([]byte("public engine transport new  key"))

func transportIdentity(t *testing.T, secret string) *enginetransport.Identity {
	t.Helper()
	b, err := enginetransport.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	i, err := enginetransport.Derive(b)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func transportServer(t *testing.T, identity *enginetransport.Identity, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = identity.ServerTLS()
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestEngineTLSClientFamilies(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", transportSecret)
	var requests atomic.Int32
	srv := transportServer(t, transportIdentity(t, transportSecret), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Complete body consumption before acknowledging dispatch to the test.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		requests.Add(1)
		if r.TLS.Version != tls.VersionTLS13 || r.ProtoMajor != 1 {
			t.Error("wrong protocol")
		}
		if r.URL.Path == "/internal/pcap/download" {
			_, _ = io.WriteString(w, "capture")
			return
		}
		_, _ = io.WriteString(w, `{"iec104Enforcement":{}}`)
	}))
	c := NewHTTPClient(srv.URL)
	defer c.Client.CloseIdleConnections()
	ctx := context.Background()
	var read map[string]any
	if err := c.getJSON(ctx, "/health", "health", &read); err != nil {
		t.Fatal(err)
	}
	if err := c.Configure(ctx, config.DataPlaneConfig{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadPcap(ctx, "test.pcap", strings.NewReader("capture")); err != nil {
		t.Fatal(err)
	}
	response, err := c.DownloadPcap(ctx, "test.pcap")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(b) != "capture" {
		t.Fatal("download failed")
	}
	if _, err := c.UploadAVDef(ctx, "test.ndb", strings.NewReader("signature")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Learn(ctx, http.MethodPost, "/learn/generate", "operator", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 6 {
		t.Fatal("missing family")
	}
}

func TestEngineTLSRefusals(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", transportSecret)
	identity := transportIdentity(t, transportSecret)
	other := transportIdentity(t, rotatedSecret)
	var dispatched atomic.Int32
	srv := transportServer(t, identity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		dispatched.Add(1)
		_, _ = io.WriteString(w, `{"iec104Enforcement":{}}`)
	}))
	noCert := identity.ClientTLS()
	noCert.Certificates = nil
	wrongCert := identity.ClientTLS()
	wrongCert.Certificates = []tls.Certificate{other.Client}
	oldTLS := identity.ClientTLS()
	oldTLS.MinVersion = tls.VersionTLS12
	oldTLS.MaxVersion = tls.VersionTLS12
	wrongServer := other.ClientTLS()
	wrongServer.Certificates = []tls.Certificate{identity.Client}
	for name, config := range map[string]*tls.Config{"TLS 1.2": oldTLS, "no client": noCert, "different self signed client": wrongCert, "wrong server identity": wrongServer, "wrong secret": other.ClientTLS()} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
			defer client.CloseIdleConnections()
			resp, err := client.Post(srv.URL+"/internal/config", "application/json", strings.NewReader(`{}`))
			if err == nil {
				resp.Body.Close()
				t.Fatal("unauthorized POST reached HTTP")
			}
		})
	}
	resp, err := http.Post(strings.Replace(srv.URL, "https:", "http:", 1)+"/internal/config", "application/json", strings.NewReader(`{}`))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatal("accepted plaintext")
		}
	}
	if dispatched.Load() != 0 {
		t.Fatal("unauthorized request dispatched")
	}
	t.Setenv("CONTAIND_ENGINE_SECRET", rotatedSecret)
	wrong := NewHTTPClient(srv.URL)
	defer wrong.Client.CloseIdleConnections()
	if _, err := wrong.RuntimeHealth(context.Background()); err == nil {
		t.Fatal("wrong secret accepted")
	}
}

func TestEngineTLSRedirectAndOrigin(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", transportSecret)
	var reached atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer destination.Close()
	srv := transportServer(t, transportIdentity(t, transportSecret), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	c := NewHTTPClient(srv.URL)
	defer c.Client.CloseIdleConnections()
	if _, err := c.RuntimeHealth(context.Background()); err == nil {
		t.Fatal("redirect followed")
	}
	request, _ := http.NewRequest(http.MethodGet, destination.URL, nil)
	if response, err := c.Client.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("cross-origin request sent")
	}
	if reached.Load() != 0 {
		t.Fatal("destination reached")
	}
	if _, err := NewHTTPClient("http://engine.internal").RuntimeHealth(context.Background()); err == nil {
		t.Fatal("plaintext remote target accepted")
	}
}

func TestEngineTLSRegenerationAndRotation(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", transportSecret)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"iec104Enforcement":{}}`) })
	srv := transportServer(t, transportIdentity(t, transportSecret), handler)
	original := NewHTTPClient(srv.URL)
	if _, err := original.RuntimeHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	original.Client.CloseIdleConnections()
	srv.Close()
	// Both peers reconstruct credentials independently, without shared files.
	regenerated := transportServer(t, transportIdentity(t, transportSecret), handler)
	client := NewHTTPClient(regenerated.URL)
	defer client.Client.CloseIdleConnections()
	if _, err := client.RuntimeHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	regenerated.Close()
	rotated := transportServer(t, transportIdentity(t, rotatedSecret), handler)
	old := NewHTTPClient(rotated.URL)
	defer old.Client.CloseIdleConnections()
	if _, err := old.RuntimeHealth(context.Background()); err == nil {
		t.Fatal("old credentials worked after restart")
	}
	t.Setenv("CONTAIND_ENGINE_SECRET", rotatedSecret)
	current := NewHTTPClient(rotated.URL)
	defer current.Client.CloseIdleConnections()
	if _, err := current.RuntimeHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
}
