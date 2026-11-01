// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

func vpnManagedAuthority(t *testing.T, cfg config.VPNConfig) *cpservices.Manager {
	t.Helper()
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", filepath.Join(root, "authority"))
	script := filepath.Join(root, "openvpn")
	body := `#!/bin/sh
set -eu
trap 'exit 0' TERM INT
while read -r option file rest; do
 case "$option" in
 ca|cert|key|crl-verify) cat "$file" >/dev/null ;;
 esac
done < "$2"
echo 'Initialization Sequence Completed'
while true; do sleep 0.02; done
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	manager := cpservices.NewVPNManager(filepath.Join(root, "services"))
	manager.OpenVPNPath, manager.SuperviseOpenVPN = script, true
	t.Cleanup(func() {
		if err := manager.Apply(context.Background(), config.VPNConfig{}); err != nil {
			t.Errorf("stop managed server: %v", err)
		}
	})
	if err := manager.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return &cpservices.Manager{VPN: manager}
}

func TestVPNClientManagedAuthority(t *testing.T) {
	cfg := config.VPNConfig{OpenVPN: config.OpenVPNConfig{Enabled: true, Mode: "server", Server: &config.OpenVPNManagedServerConfig{
		TunnelCIDR: "10.9.0.0/24", PublicEndpoint: "vpn.example.com",
	}}}
	svc := vpnManagedAuthority(t, cfg)
	// The candidate has no server at all; authority operations must still use
	// the active manager's issuer and endpoint.
	server := NewServerWithEngineAndServices(&mockStore{cfg: config.DefaultConfig()}, nil, nil, svc, nil)
	rec := vpnRequest(server, "POST", "/clients", `{"name":"alice"}`)
	var credential cpservices.OpenVPNCredential
	if err := json.Unmarshal(rec.Body.Bytes(), &credential); err != nil || rec.Code != http.StatusOK || credential.ID == "" {
		t.Fatalf("create: %d %s %v", rec.Code, rec.Body, err)
	}
	rec = vpnRequest(server, "POST", "/clients", `{"name":"alice"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"unknown", "alice"} {
		rec = vpnRequest(server, "GET", "/clients/"+id, "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET issued or accepted a name alias: %d %s", rec.Code, rec.Body)
		}
	}
	rec = vpnRequest(server, "GET", "/clients/"+credential.ID, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "remote vpn.example.com 1194") {
		t.Fatalf("download: %d %s", rec.Code, rec.Body)
	}
	// Removing the daemon executable makes runtime confirmation impossible but
	// cannot prevent or roll back the durable revocation.
	svc.VPN.OpenVPNPath = filepath.Join(t.TempDir(), "missing-openvpn")
	rec = vpnRequest(server, "POST", "/clients/"+credential.ID+"/revoke", "")
	var result cpservices.OpenVPNRevokeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || rec.Code != http.StatusServiceUnavailable || !result.Revoked || result.Applied {
		t.Fatalf("partial revoke: %d %s %v", rec.Code, rec.Body, err)
	}
	rec = vpnRequest(server, "GET", "/clients/"+credential.ID, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("revoked credential downloadable: %d %s", rec.Code, rec.Body)
	}
}

func TestRemoteAccessProfileParserRefusesBeforePublication(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", root)
	active := filepath.Join(root, "active.ovpn")
	original := []byte("client\nremote active.example.com 1194\n")
	if err := os.WriteFile(active, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store := stageStore(t)
	server := NewServer(store, nil)
	for _, profile := range []string{
		"client\ndaemon\n", "client\nup evil\n", "client\nscript-security 2\n",
		"client\nplugin evil\n", "client\nconfig nested.ovpn\n", "client\nmanagement localhost 5555\n",
		"client\nca external.pem\n", "client\n--remote vpn.example.com\n",
		"client\nremote vpn.example.com 1194\\\nproto udp\n",
		"client\n<ca>\nbytes\n</ca> up evil\n", "client\nunknown-option value\n",
		"client\nremote vpn.example.com 1194 extra extra\n", "client\r",
		strings.Repeat("#", (1<<20)+1),
	} {
		rec := requestStage(t, server, "POST", "/services/vpn/openvpn/profile", map[string]string{"name": "unsafe", "ovpn": profile})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("profile accepted: status=%d body=%s", rec.Code, rec.Body)
		}
		candidateSnapshot, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
		candidate := candidateSnapshot.Candidate
		if err != nil || candidate.Services.VPN.OpenVPN.ConfigPath != "" {
			t.Fatalf("refusal staged a profile: %+v %v", candidate, err)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 1 {
			t.Fatalf("refusal published files: %+v %v", entries, err)
		}
		data, err := os.ReadFile(active)
		if err != nil || string(data) != string(original) {
			t.Fatalf("refusal modified active profile: %s %v", data, err)
		}
	}
}

func TestRemoteAccessProfileInlineImport(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", root)
	store := stageStore(t)
	server := NewServer(store, nil)
	profile := "client\nremote vpn.example.com 1194\nproto udp\n<ca>\ninline-ca\n</ca>\n<cert>\ninline-cert\n</cert>\n<key>\ninline-key\n</key>\n"
	rec := requestStage(t, server, "POST", "/services/vpn/openvpn/profile", map[string]string{"name": "bounded", "ovpn": profile})
	if rec.Code != http.StatusOK {
		t.Fatalf("bounded import: %d %s", rec.Code, rec.Body)
	}
	candidateSnapshot, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
	candidate := candidateSnapshot.Candidate
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(candidate.Services.VPN.OpenVPN.ConfigPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile permissions: %v %v", info, err)
	}
	running, err := store.Load(context.Background())
	if err != nil || running.Services.VPN.OpenVPN.ConfigPath != "" {
		t.Fatalf("upload changed running config: %+v %v", running, err)
	}
}
