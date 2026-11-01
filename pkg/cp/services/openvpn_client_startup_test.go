// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestOpenVPNConnectingClientIsNotQuarantined(t *testing.T) {
	for _, imported := range []bool{false, true} {
		t.Run(map[bool]string{false: "managed", true: "imported"}[imported], func(t *testing.T) {
			vpn, _ := openVPNFakeManager(t)
			root := t.TempDir()
			script := filepath.Join(root, "connecting")
			body := `#!/bin/sh
set -eu
trap 'exit 0' TERM INT
until [ -f '` + root + `/connect' ]; do sleep 0.02; done
echo 'Initialization Sequence Completed'
until [ -f '` + root + `/restart' ]; do sleep 0.02; done
echo 'SIGUSR1[soft,ping-restart] received, process restarting'
until [ -f '` + root + `/reconnect' ]; do sleep 0.02; done
echo 'Initialization Sequence Completed'
until [ -f '` + root + `/exit' ]; do sleep 0.02; done
exit 7
`
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			vpn.OpenVPNPath = script
			cfg := config.ServicesConfig{VPN: config.VPNConfig{OpenVPN: config.OpenVPNConfig{
				Enabled: true, Mode: "client",
				Managed: &config.OpenVPNManagedClientConfig{Remote: "vpn.example.test", CA: "ca", Cert: "cert", Key: "key"},
			}}}
			if imported {
				path := filepath.Join(root, "import.ovpn")
				if err := os.WriteFile(path, []byte("client\nremote vpn.example.test 1194\n<ca>\nca\n</ca>\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.VPN.OpenVPN.Managed = nil
				cfg.VPN.OpenVPN.ConfigPath = path
			}
			manager := NewManager(ManagerOptions{BaseDir: t.TempDir()})
			manager.Syslog, manager.DNS, manager.NTP, manager.Proxy, manager.DHCP = nil, nil, nil, nil, nil
			manager.VPN = vpn
			effective, warnings := manager.ApplyEffective(context.Background(), cfg, nil)
			if !effective.VPN.OpenVPN.Enabled || len(warnings) != 0 || len(manager.Faults()) != 0 {
				t.Fatalf("connecting client quarantined: %+v %v %v", effective.VPN.OpenVPN, warnings, manager.Faults())
			}
			assertConnection := func(running, connected bool) {
				t.Helper()
				status := vpn.Status()
				if status["openvpn_running"] != running || status["openvpn_connected"] != connected {
					t.Fatalf("want running=%t connected=%t: %+v", running, connected, status)
				}
			}
			assertConnection(true, false)
			pid := vpn.Status()["openvpn_pid"]
			// A no-op apply must preserve the connecting daemon.
			openVPNApply(t, vpn, cfg.VPN)
			if vpn.Status()["openvpn_pid"] != pid {
				t.Fatal("no-op apply restarted connecting client")
			}
			for _, step := range []struct {
				file      string
				running   bool
				connected bool
			}{
				{"connect", true, true},
				{"restart", true, false},
				{"reconnect", true, true},
				{"exit", false, false},
			} {
				if err := os.WriteFile(filepath.Join(root, step.file), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				waitFor(t, 2*time.Second, func() bool {
					status := vpn.Status()
					return status["openvpn_running"] == step.running && status["openvpn_connected"] == step.connected
				})
				assertConnection(step.running, step.connected)
			}
		})
	}
}

func TestOpenVPNClientEarlyExitFails(t *testing.T) {
	for _, marker := range []bool{false, true} {
		t.Run(map[bool]string{false: "parse-error", true: "exit-after-marker"}[marker], func(t *testing.T) {
			m, _ := openVPNFakeManager(t)
			body := "#!/bin/sh\n"
			if marker {
				body += "echo 'Initialization Sequence Completed'\n"
			}
			body += "exit 7\n"
			script := filepath.Join(t.TempDir(), "early-exit")
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			m.OpenVPNPath = script
			cfg := config.VPNConfig{OpenVPN: config.OpenVPNConfig{Enabled: true,
				Managed: &config.OpenVPNManagedClientConfig{Remote: "vpn.example.test", CA: "ca", Cert: "cert", Key: "key"}}}
			if err := m.Apply(context.Background(), cfg); err == nil {
				t.Fatal("early client exit accepted")
			}
			if status := m.Status(); status["openvpn_running"] != false || status["openvpn_connected"] != false {
				t.Fatalf("exited client is active: %+v", status)
			}
		})
	}
}

func TestOpenVPNServerStillRequiresReadiness(t *testing.T) {
	m, _ := openVPNFakeManager(t)
	script := filepath.Join(t.TempDir(), "not-ready")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile true; do sleep 0.02; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.OpenVPNPath = script
	if err := m.Apply(context.Background(), openVPNServerConfig()); err == nil || !strings.Contains(err.Error(), "readiness timed out") {
		t.Fatalf("server without marker did not fail: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ovpnRunning || m.ovpnCRLNumber != 0 {
		t.Fatal("unready server acknowledged CRL or leaked daemon")
	}
}

func TestOpenVPNConnectionMarkers(t *testing.T) {
	w := newOpenVPNReadyWriter(io.Discard)
	for _, step := range []struct {
		text string
		up   bool
	}{
		{"Initialization Sequence ", false},
		{"Completed\n", true},
		{"SIGUSR", true},
		{"1[soft,connection-reset] received, process restarting\n", false},
		{"Initialization Sequence Completed\n", true},
		{"SIGUSR1[soft,ping-restart]\nInitialization Sequence Completed\n", true},
		{"Initialization Sequence Completed\nSIGUSR1[soft,ping-restart]\n", false},
	} {
		if _, err := w.Write([]byte(step.text)); err != nil {
			t.Fatal(err)
		}
		if w.connected() != step.up {
			t.Fatalf("after %q want connected=%t", step.text, step.up)
		}
	}
}
