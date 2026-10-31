// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

const vpnTestID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1234"

type vpnClientServices struct {
	credentials []cpservices.OpenVPNCredential
	applied     bool
	names       []string
	downloads   []string
	revokes     []string
	err         error
	result      cpservices.OpenVPNRevokeResult
}

func (*vpnClientServices) Apply(context.Context, config.ServicesConfig) error { return nil }
func (s *vpnClientServices) ListOpenVPNClients(context.Context) (cpservices.OpenVPNClientList, error) {
	return cpservices.OpenVPNClientList{Clients: s.credentials, RevocationsApplied: s.applied}, s.err
}
func (s *vpnClientServices) CreateOpenVPNClient(_ context.Context, name string) (cpservices.OpenVPNCredential, error) {
	s.names = append(s.names, name)
	if s.err != nil {
		return cpservices.OpenVPNCredential{}, s.err
	}
	credential := cpservices.OpenVPNCredential{
		ID: vpnTestID, Issuer: strings.Repeat("a", 64), Serial: "1234", Name: name,
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	s.credentials = append(s.credentials, credential)
	return credential, nil
}
func (s *vpnClientServices) DownloadOpenVPNClient(_ context.Context, id string) ([]byte, error) {
	s.downloads = append(s.downloads, id)
	return []byte("client\nremote vpn.example.com 1194\n<ca>\ntest-ca\n</ca>\n"), s.err
}
func (s *vpnClientServices) RevokeOpenVPNClient(_ context.Context, id string) (cpservices.OpenVPNRevokeResult, error) {
	s.revokes = append(s.revokes, id)
	return s.result, s.err
}

func vpnRequest(server http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := authedRequest(method, "/api/v1/services/vpn/openvpn"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	server.ServeHTTP(rec, req)
	return rec
}

func TestVPNClientAuthorityRoutes(t *testing.T) {
	// Credential operations must never consult a stale candidate or running
	// document. Only the service capability selects the active authority.
	store := &mockStore{load: func() (*config.Config, error) {
		t.Error("credential operation read configuration")
		return nil, errors.New("unexpected load")
	}}
	svc := &vpnClientServices{}
	audits := &mockAuditStore{}
	server := NewServerWithEngineAndServices(store, audits, nil, svc, nil)
	created := vpnRequest(server, http.MethodPost, "/clients", `{"name":"labuser01"}`)
	var credential cpservices.OpenVPNCredential
	if err := json.Unmarshal(created.Body.Bytes(), &credential); err != nil || created.Code != http.StatusOK || credential.ID != vpnTestID {
		t.Fatalf("create: %d %s %v", created.Code, created.Body, err)
	}
	listed := vpnRequest(server, http.MethodGet, "/clients", "")
	var listing struct {
		Clients []cpservices.OpenVPNCredential `json:"clients"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &listing); err != nil || listed.Code != http.StatusOK || len(listing.Clients) != 1 || listing.Clients[0].ID != credential.ID {
		t.Fatalf("list: %d %s %v", listed.Code, listed.Body, err)
	}
	for range 2 {
		downloaded := vpnRequest(server, http.MethodGet, "/clients/"+credential.ID, "")
		if downloaded.Code != http.StatusOK || !strings.Contains(downloaded.Body.String(), "<ca>") || downloaded.Header().Get("Content-Type") != "application/x-openvpn-profile" {
			t.Fatalf("download: %d %s", downloaded.Code, downloaded.Body)
		}
	}
	if len(svc.names) != 1 || len(svc.downloads) != 2 || svc.downloads[0] != credential.ID || svc.downloads[1] != credential.ID {
		t.Fatalf("GET issued or changed identity: %+v", svc)
	}
	svc.result = cpservices.OpenVPNRevokeResult{Credential: credential, Revoked: true, Applied: true}
	revoked := vpnRequest(server, http.MethodPost, "/clients/"+credential.ID+"/revoke", "")
	if revoked.Code != http.StatusOK || len(svc.revokes) != 1 || svc.revokes[0] != credential.ID {
		t.Fatalf("revoke: %d %s %+v", revoked.Code, revoked.Body, svc.revokes)
	}
	if len(audits.records) != 2 || audits.records[0].Action != "services.vpn.openvpn.client.create" || audits.records[1].Action != "services.vpn.openvpn.client.revoke" {
		t.Fatalf("expected one create and one revoke audit: %+v", audits.records)
	}
	for _, record := range audits.records {
		if record.Target != credential.ID {
			t.Fatalf("audit did not use authority ID: %+v", record)
		}
	}
}

func TestVPNClientCapabilityErrors(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		err                      error
		status                   int
	}{
		{"duplicate", "POST", "/clients", `{"name":"alice"}`, cpservices.ErrOpenVPNClientNameIssued, 409},
		{"invalid", "POST", "/clients", `{"name":"Alice"}`, cpservices.ErrOpenVPNInvalidClientName, 400},
		{"inactive", "POST", "/clients", `{"name":"alice"}`, cpservices.ErrOpenVPNServerNotActive, 409},
		{"download-missing", "GET", "/clients/missing", "", cpservices.ErrOpenVPNUnknownCredential, 404},
		{"revoke-missing", "POST", "/clients/missing/revoke", "", cpservices.ErrOpenVPNUnknownCredential, 404},
		{"download-revoked", "GET", "/clients/" + vpnTestID, "", cpservices.ErrOpenVPNCredentialRevoked, 409},
		{"list-failed", "GET", "/clients", "", errors.New("inventory read failed"), 500},
		{"create-failed", "POST", "/clients", `{"name":"alice"}`, errors.New("server certificate failed"), 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &vpnClientServices{err: fmt.Errorf("authority: %w", tc.err)}
			audits := &mockAuditStore{}
			server := NewServerWithEngineAndServices(&mockStore{}, audits, nil, svc, nil)
			rec := vpnRequest(server, tc.method, tc.path, tc.body)
			if rec.Code != tc.status || len(audits.records) != 0 {
				t.Fatalf("response %d %s audits=%+v", rec.Code, rec.Body, audits.records)
			}
		})
	}
}

func TestVPNClientRevokeUnconfirmed(t *testing.T) {
	for _, backendErr := range []error{errors.New("restart failed"), nil} {
		svc := &vpnClientServices{
			result: cpservices.OpenVPNRevokeResult{Credential: cpservices.OpenVPNCredential{ID: vpnTestID}, Revoked: true},
			err:    backendErr,
		}
		audits := &mockAuditStore{}
		server := NewServerWithEngineAndServices(&mockStore{}, audits, nil, svc, nil)
		rec := vpnRequest(server, "POST", "/clients/"+vpnTestID+"/revoke", "")
		var result cpservices.OpenVPNRevokeResult
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || rec.Code != http.StatusServiceUnavailable || !result.Revoked || result.Applied || result.Credential.ID != vpnTestID {
			t.Fatalf("lost durable result: %d %s %v", rec.Code, rec.Body, err)
		}
		if len(audits.records) != 1 || !strings.Contains(audits.records[0].Detail, "applied=false") {
			t.Fatalf("missing partial-revoke audit: %+v", audits.records)
		}
	}
}

func TestVPNClientAuthorizationAndUnavailable(t *testing.T) {
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "vpn-viewer")
	svc := &vpnClientServices{}
	server := NewServerWithEngineAndServices(&mockStore{}, nil, nil, svc, nil)
	for _, route := range []struct{ method, path string }{
		{"GET", "/clients"}, {"POST", "/clients"}, {"GET", "/clients/" + vpnTestID},
		{"POST", "/clients/" + vpnTestID + "/revoke"}, {"POST", "/profile"},
	} {
		for _, token := range []string{"", "vpn-viewer"} {
			req := httptest.NewRequest(route.method, "/api/v1/services/vpn/openvpn"+route.path, strings.NewReader(`{"name":"alice"}`))
			want := http.StatusUnauthorized
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
				want = http.StatusForbidden
			}
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != want {
				t.Fatalf("%s %s: %d %s", route.method, route.path, rec.Code, rec.Body)
			}
		}
	}
	if len(svc.names)+len(svc.downloads)+len(svc.revokes) != 0 {
		t.Fatal("unauthorized request reached authority")
	}
	unavailable := NewServer(&mockStore{}, nil)
	for _, route := range []struct{ method, path string }{
		{"GET", "/clients"}, {"POST", "/clients"}, {"GET", "/clients/" + vpnTestID}, {"POST", "/clients/" + vpnTestID + "/revoke"},
	} {
		rec := vpnRequest(unavailable, route.method, route.path, `{"name":"alice"}`)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("missing capability: %d %s", rec.Code, rec.Body)
		}
	}
}

func TestVPNClientListRevocationsApplied(t *testing.T) {
	for _, applied := range []bool{false, true} {
		svc := &vpnClientServices{credentials: []cpservices.OpenVPNCredential{}, applied: applied}
		server := NewServerWithEngineAndServices(&mockStore{}, nil, nil, svc, nil)
		rec := vpnRequest(server, "GET", "/clients", "")
		var listing struct {
			Clients []cpservices.OpenVPNCredential `json:"clients"`
			Applied *bool                          `json:"revocationsApplied"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil || rec.Code != http.StatusOK || listing.Applied == nil || *listing.Applied != applied || listing.Clients == nil {
			t.Fatalf("list applied=%t: %d %s %v", applied, rec.Code, rec.Body, err)
		}
	}
}
