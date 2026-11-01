// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func daemonWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func daemonUnchanged(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("active file changed: %s = %q, %v", path, data, err)
	}
}

func daemonFault(t *testing.T, err error, service string) {
	t.Helper()
	var fault *config.ServiceConfigError
	if !errors.As(err, &fault) || fault.Service != service {
		t.Fatalf("want %s config fault, got %v", service, err)
	}
}

// A real, unrelated-to-the-daemon sleep child makes stop/restart side effects
// observable without depending on binaries installed on the test host.
func daemonSentinel(t *testing.T) (*exec.Cmd, chan struct{}) {
	t.Helper()
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("sentinel not reaped")
		}
	})
	return cmd, done
}

func daemonStillRunning(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("invalid config stopped the current process")
	default:
	}
}

func TestDaemonRefusesUnsafeSinksBeforeSideEffects(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []string{"\r", "\n", "\x00", ";", "{", "}", "#", "\"", "'", "../escape"} {
		t.Run("input_"+strings.ReplaceAll(bad, "/", "_"), func(t *testing.T) {
			t.Run("proxy", func(t *testing.T) {
				m := NewProxyManager(ProxyOptions{BaseDir: t.TempDir(), Supervise: true})
				cmd, done := daemonSentinel(t)
				m.nginxCmd, m.nginxDone = cmd, done
				path := filepath.Join(m.BaseDir, "nginx-reverse.conf")
				daemonWrite(t, path, "current")
				mutations := []func(*config.ProxyConfig){
					func(c *config.ProxyConfig) { c.Reverse.Sites[0].Name += bad },
					func(c *config.ProxyConfig) { c.Reverse.Sites[0].Hostnames = []string{"example.test" + bad} },
					func(c *config.ProxyConfig) { c.Reverse.Sites[0].Backends = []string{"localhost:80" + bad} },
					func(c *config.ProxyConfig) { c.Reverse.Sites[0].CertRef = "cert" + bad },
					func(c *config.ProxyConfig) { c.Forward.AllowedDomains = []string{"example.test" + bad} },
					func(c *config.ProxyConfig) { c.Forward.ListenZones = []string{"lan" + bad} },
					func(c *config.ProxyConfig) { c.Forward.Upstream = bad },
					func(c *config.ProxyConfig) { c.Forward.AllowedClients = []string{bad} },
				}
				for _, enabled := range []bool{true, false} {
					for _, mutate := range mutations {
						cfg := daemonProxyConfig()
						cfg.Reverse.Enabled = enabled
						mutate(&cfg)
						daemonFault(t, m.Apply(ctx, cfg), config.ServiceProxy)
						daemonFault(t, m.Validate(ctx, cfg), config.ServiceProxy)
						daemonUnchanged(t, path, "current")
						daemonStillRunning(t, done)
						if m.nginxCmd != cmd || m.lastCfg.Reverse.Enabled {
							t.Fatal("invalid config changed state")
						}
					}
				}
			})
			t.Run("dns", func(t *testing.T) {
				m := NewDNSManager(t.TempDir())
				cmd, done := daemonSentinel(t)
				m.cmd, m.done, m.running = cmd, done, true
				path := filepath.Join(m.BaseDir, "unbound.conf")
				daemonWrite(t, path, "current")
				for _, enabled := range []bool{true, false} {
					cfg := config.DNSConfig{Enabled: enabled, UpstreamServers: []string{"1.1.1.1" + bad}}
					daemonFault(t, m.Apply(ctx, cfg), config.ServiceDNS)
					daemonFault(t, m.Validate(ctx, cfg), config.ServiceDNS)
					daemonUnchanged(t, path, "current")
					daemonStillRunning(t, done)
					if m.cmd != cmd || m.lastCfg.Enabled {
						t.Fatal("invalid config changed state")
					}
				}
			})
			t.Run("ntp", func(t *testing.T) {
				m := NewNTPManager(t.TempDir())
				cmd, done := daemonSentinel(t)
				m.cmd = cmd
				path := m.configPath()
				daemonWrite(t, path, "current")
				for _, enabled := range []bool{true, false} {
					cfg := config.NTPConfig{Enabled: enabled, Servers: []string{"time.example" + bad}}
					daemonFault(t, m.Apply(ctx, cfg), config.ServiceNTP)
					daemonFault(t, m.Validate(ctx, cfg), config.ServiceNTP)
					daemonUnchanged(t, path, "current")
					daemonStillRunning(t, done)
					if m.cmd != cmd || m.lastCfg.Enabled {
						t.Fatal("invalid config changed state")
					}
				}
			})
			t.Run("av", func(t *testing.T) {
				m := NewAVManager(ctx, AVOptions{StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
				t.Cleanup(m.cancel)
				cmd, done := daemonSentinel(t)
				m.clamd.cmd, m.clamd.done = cmd, done
				for _, path := range []string{m.clamdConfPath(), m.freshclamConfPath()} {
					daemonWrite(t, path, "current")
				}
				for _, enabled := range []bool{true, false} {
					socket := "/run/clamd.sock" + bad
					if bad == "../escape" {
						socket = "/run/../escape"
					}
					cfg := config.AVConfig{Enabled: enabled, ClamAV: config.ClamAVConfig{SocketPath: socket}}
					daemonFault(t, m.Apply(ctx, cfg), config.ServiceAV)
					daemonFault(t, m.Validate(ctx, cfg), config.ServiceAV)
					for _, path := range []string{m.clamdConfPath(), m.freshclamConfPath()} {
						daemonUnchanged(t, path, "current")
					}
					daemonStillRunning(t, done)
					if m.clamd.cmd != cmd || m.Current().Enabled {
						t.Fatal("invalid config changed state")
					}
				}
			})
		})
	}
}

func daemonProxyConfig() config.ProxyConfig {
	return config.ProxyConfig{Reverse: config.ReverseProxyConfig{Enabled: true, Sites: []config.ReverseProxySite{{Name: "app", ListenPort: 8443, Backends: []string{"127.0.0.1:80"}}}}}
}

func TestDaemonPreflightFailurePreservesFilesAndState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	binary := filepath.Join(dir, "reject-config")
	daemonWrite(t, binary, "#!/bin/sh\necho invalid >&2\nexit 1\n")
	if err := os.Chmod(binary, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Run("proxy_checks_both_before_publishing", func(t *testing.T) {
		m := NewProxyManager(ProxyOptions{BaseDir: t.TempDir(), NginxPath: binary, EnvoyPath: "/nonexistent/envoy"})
		for _, file := range m.DescribeRendered() {
			daemonWrite(t, file, "current")
		}
		cfg := daemonProxyConfig()
		cfg.Forward.Enabled = true
		for _, enabled := range []bool{true, false} {
			cfg.Forward.Enabled = enabled
			daemonFault(t, m.Apply(ctx, cfg), config.ServiceProxy)
			for _, file := range m.DescribeRendered() {
				daemonUnchanged(t, file, "current")
			}
		}
		if !reflect.DeepEqual(m.lastCfg, config.ProxyConfig{}) {
			t.Fatal("failed apply changed state")
		}
	})
	t.Run("dns", func(t *testing.T) {
		m := NewDNSManager(t.TempDir())
		m.Supervise, m.CheckConfPath = false, binary
		path := filepath.Join(m.BaseDir, "unbound.conf")
		daemonWrite(t, path, "current")
		daemonFault(t, m.Apply(ctx, config.DNSConfig{Enabled: true}), config.ServiceDNS)
		daemonUnchanged(t, path, "current")
		if m.Current().Enabled {
			t.Fatal("failed apply changed state")
		}
	})
	t.Run("ntp", func(t *testing.T) {
		m := NewNTPManager(t.TempDir())
		m.Supervise, m.NTPDPath = false, binary
		daemonWrite(t, m.configPath(), "current")
		daemonFault(t, m.Apply(ctx, config.NTPConfig{Enabled: true}), config.ServiceNTP)
		daemonUnchanged(t, m.configPath(), "current")
		if m.Current().Enabled {
			t.Fatal("failed apply changed state")
		}
	})
}

func TestDaemonValidConfigurationsRender(t *testing.T) {
	ctx := context.Background()
	dns := NewDNSManager(t.TempDir())
	dns.Supervise, dns.CheckConfPath = false, ""
	cfg := config.DNSConfig{Enabled: true, ListenPort: 5353, CacheSizeMB: 16, UpstreamServers: []string{"1.1.1.1@5353", "2001:db8::1"}}
	if err := dns.Validate(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := dns.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	daemonUnchanged(t, filepath.Join(dns.BaseDir, "unbound.conf"), renderUnbound(cfg))
	ntp := NewNTPManager(t.TempDir())
	ntp.Supervise, ntp.NTPDPath = false, ""
	ncfg := config.NTPConfig{Enabled: true, Servers: []string{"time.example", "2001:db8::1"}}
	if err := ntp.Validate(ctx, ncfg); err != nil {
		t.Fatal(err)
	}
	if err := ntp.Apply(ctx, ncfg); err != nil {
		t.Fatal(err)
	}
	daemonUnchanged(t, ntp.configPath(), ntp.renderChronyConfig(ncfg))
}

func TestAVDaemonConfigPaths(t *testing.T) {
	m := NewAVManager(context.Background(), AVOptions{StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
	t.Cleanup(m.cancel)
	cfg := config.AVConfig{Enabled: true, Mode: "clamav", ClamAV: config.ClamAVConfig{SocketPath: "/run/clamd.sock"}}
	if err := m.Validate(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LocalSocket /run/clamd.sock\n", "DatabaseDirectory " + m.opts.DatabaseDir + "\n"} {
		if !strings.Contains(m.renderClamdConf(cfg), want) {
			t.Fatalf("missing %q", want)
		}
	}
	if !strings.Contains(m.renderFreshclamConf(), "DatabaseDirectory "+m.opts.DatabaseDir+"\n") {
		t.Fatal("missing freshclam database directory")
	}
	for _, path := range []string{m.clamdConfPath(), m.freshclamConfPath()} {
		daemonWrite(t, path, "current")
	}
	for _, bad := range []string{"/var/lib/clamav\nDatabaseMirror attacker", "/var/lib/../clamav", "/var/lib/clamav\x00", "/var/lib/clamav;"} {
		m.opts.DatabaseDir = bad
		daemonFault(t, m.Apply(context.Background(), cfg), config.ServiceAV)
		for _, path := range []string{m.clamdConfPath(), m.freshclamConfPath()} {
			daemonUnchanged(t, path, "current")
		}
	}
}

func TestDaemonPreflightReadsStagedFiles(t *testing.T) {
	for _, kind := range []string{"proxy", "dns", "ntp"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			active := filepath.Join(dir, "active")
			daemonWrite(t, active, "current")
			binary := filepath.Join(dir, "check")
			daemonWrite(t, binary, "#!/bin/sh\nfor arg do conf=\"$arg\"; done\n"+
				"test \"$(cat '"+active+"')\" = current || exit 10\n"+
				"case \"$conf\" in '"+dir+"'/.*) ;; *) exit 11;; esac\n"+
				"test -s \"$conf\" || exit 12\n")
			if err := os.Chmod(binary, 0o700); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			switch kind {
			case "proxy":
				m := NewProxyManager(ProxyOptions{BaseDir: dir, EnvoyPath: binary, NginxPath: binary})
				cfg := daemonProxyConfig()
				cfg.Forward.Enabled = true
				if err := m.Apply(ctx, cfg); err != nil {
					t.Fatal(err)
				}
			case "dns":
				m := NewDNSManager(dir)
				m.Supervise, m.CheckConfPath = false, binary
				if err := m.Apply(ctx, config.DNSConfig{Enabled: true}); err != nil {
					t.Fatal(err)
				}
			case "ntp":
				m := NewNTPManager(dir)
				m.Supervise, m.NTPDPath = false, binary
				if err := m.Apply(ctx, config.NTPConfig{Enabled: true}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
