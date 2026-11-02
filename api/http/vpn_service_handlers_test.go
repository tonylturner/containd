// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func assertVPNRead(t *testing.T, body []byte, configured bool) {
	t.Helper()
	var view struct {
		WireGuard map[string]any `json:"wireguard"`
		OpenVPN   struct {
			Managed map[string]any `json:"managed"`
		} `json:"openvpn"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if v, present := view.WireGuard["privateKeyConfigured"]; !present || v != configured {
		t.Fatalf("private key presence: %s", body)
	}
	if _, present := view.WireGuard["privateKey"]; present {
		t.Fatalf("private key returned: %s", body)
	}
	for _, secret := range []string{"ca", "cert", "key", "password"} {
		if v, present := view.OpenVPN.Managed[secret+"Configured"]; !present || v != configured {
			t.Fatalf("%s presence: %s", secret, body)
		}
		if _, present := view.OpenVPN.Managed[secret]; present {
			t.Fatalf("%s returned: %s", secret, body)
		}
	}
}

func TestVPNSecretPresence(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "unset", true: "set"}[configured], func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Services.VPN.OpenVPN.Managed = &config.OpenVPNManagedClientConfig{}
			if configured {
				cfg.Services.VPN.WireGuard.PrivateKey = "private-material"
				cfg.Services.VPN.OpenVPN.Managed = &config.OpenVPNManagedClientConfig{
					CA: "ca-material", Cert: "cert-material", Key: "key-material", Password: "password-material",
				}
			}
			server := NewServer(&mockStore{cfg: cfg}, nil)
			rec := requestStage(t, server, "GET", "/services/vpn", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("read: %d %s", rec.Code, rec.Body)
			}
			assertVPNRead(t, rec.Body.Bytes(), configured)
			if strings.Contains(rec.Body.String(), "-material") {
				t.Fatal("stored material returned")
			}
			if configured && cfg.Services.VPN.OpenVPN.Managed.Key == "" {
				t.Fatal("read mutated source")
			}
		})
	}
}

func TestVPNSecretWriteRoundTrip(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	vpn := config.VPNConfig{
		WireGuard: config.WireGuardConfig{PrivateKey: "server-private-material"},
		OpenVPN: config.OpenVPNConfig{Managed: &config.OpenVPNManagedClientConfig{
			Remote: "vpn.example.test", CA: "ca-material", Cert: "cert-material", Key: "key-material", Password: "password-material",
		}},
	}
	rec := requestStage(t, server, "POST", "/services/vpn", vpn)
	if rec.Code != http.StatusOK {
		t.Fatalf("write: %d %s", rec.Code, rec.Body)
	}
	assertVPNRead(t, rec.Body.Bytes(), true)
	// A read/write round trip contains no secrets. Omitted and explicitly empty
	// fields both retain existing secrets while managed mode remains selected.
	for _, body := range []any{
		json.RawMessage(rec.Body.Bytes()),
		config.VPNConfig{OpenVPN: config.OpenVPNConfig{Managed: &config.OpenVPNManagedClientConfig{Remote: "vpn.example.test"}}},
		json.RawMessage(`{"wireguard":{"privateKeyConfigured":false},"openvpn":{"managed":{"remote":"vpn.example.test","caConfigured":false,"certConfigured":false,"keyConfigured":false,"passwordConfigured":false}}}`),
	} {
		rec = requestStage(t, server, "POST", "/services/vpn", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("round trip: %d %s", rec.Code, rec.Body)
		}
		assertVPNRead(t, rec.Body.Bytes(), true)
		snapshot, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
		if err != nil {
			t.Fatal(err)
		}
		got := snapshot.Candidate.Services.VPN
		if got.WireGuard.PrivateKey != vpn.WireGuard.PrivateKey || *got.OpenVPN.Managed != *vpn.OpenVPN.Managed {
			t.Fatalf("round trip lost secrets: %+v", got.RedactedVPNCopy())
		}
	}
	rec = requestStage(t, server, "POST", "/services/vpn", config.VPNConfig{})
	if rec.Code != http.StatusOK {
		t.Fatalf("remove managed mode: %d %s", rec.Code, rec.Body)
	}
	snapshot, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
	if err != nil || snapshot.Candidate.Services.VPN.OpenVPN.Managed != nil {
		t.Fatalf("omitting managed should remove the managed object: %v", err)
	}
	running, err := store.Load(context.Background())
	if err != nil || running.Services.VPN.WireGuard.PrivateKey != "" {
		t.Fatalf("staging changed running config: %v", err)
	}
}

func TestVPNSecretProfileUpload(t *testing.T) {
	t.Setenv("CONTAIND_OPENVPN_DIR", t.TempDir())
	store := stageStore(t)
	server := NewServer(store, nil)
	rec := requestStage(t, server, "POST", "/services/vpn", config.VPNConfig{
		WireGuard: config.WireGuardConfig{PrivateKey: "server-private-material"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	rec = requestStage(t, server, "POST", "/services/vpn/openvpn/profile", map[string]string{
		"name": "bounded", "ovpn": "client\nremote vpn.example.com 1194\nproto udp\n",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	var response struct {
		VPN struct {
			WireGuard map[string]any `json:"wireguard"`
		} `json:"vpn"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.VPN.WireGuard["privateKeyConfigured"] != true {
		t.Fatalf("presence missing: %s", rec.Body)
	}
	if _, present := response.VPN.WireGuard["privateKey"]; present || strings.Contains(rec.Body.String(), "private-material") {
		t.Fatal("profile upload exposed a stored private key")
	}
}
