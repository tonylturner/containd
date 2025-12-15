package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

// VPNManager persists VPN service configuration and supervises optional VPN daemons.
// WireGuard is applied in the engine (kernel netlink). OpenVPN is supervised here when enabled.
type VPNManager struct {
	BaseDir          string
	SuperviseOpenVPN bool
	OpenVPNPath      string
	OnEvent          func(kind string, attrs map[string]any)

	mu         sync.Mutex
	lastCfg    config.VPNConfig
	lastRender time.Time
	lastError  string

	ovpnCmd        *exec.Cmd
	ovpnRunning    bool
	ovpnConfigPath string
	ovpnLastStart  time.Time
	ovpnLastStop   time.Time
	ovpnLastExit   string
	ovpnLastError  string
}

func NewVPNManager(baseDir string) *VPNManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	supervise := true
	if v := strings.TrimSpace(os.Getenv("CONTAIND_SUPERVISE_OPENVPN")); v != "" && v != "1" && !strings.EqualFold(v, "true") {
		supervise = false
	}
	openvpnPath, _ := detectBinary([]string{
		strings.TrimSpace(os.Getenv("CONTAIND_OPENVPN_PATH")),
		"/usr/sbin/openvpn",
		"/usr/bin/openvpn",
	})
	return &VPNManager{BaseDir: baseDir, SuperviseOpenVPN: supervise, OpenVPNPath: openvpnPath}
}

func (m *VPNManager) Apply(ctx context.Context, cfg config.VPNConfig) error {
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.mu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "vpn.json")
	if !cfg.WireGuard.Enabled && !cfg.OpenVPN.Enabled {
		_ = m.stopOpenVPN()
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.ovpnLastError = ""
		m.mu.Unlock()
		return nil
	}

	// Render as JSON for now. WireGuard/OpenVPN runtime integration will consume this.
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()

	// OpenVPN supervision (optional)
	if cfg.OpenVPN.Enabled {
		configPath, err := m.openVPNConfigPathForEnabled(cfg.OpenVPN)
		if err != nil {
			m.mu.Lock()
			m.ovpnLastError = err.Error()
			m.mu.Unlock()
			m.emit("service.vpn.openvpn.invalid", map[string]any{"error": err.Error()})
			return err
		}
		if m.SuperviseOpenVPN && m.OpenVPNPath != "" {
			if err := m.startOpenVPN(configPath); err != nil {
				m.mu.Lock()
				m.ovpnLastError = err.Error()
				m.mu.Unlock()
				m.emit("service.vpn.openvpn.start_failed", map[string]any{"error": err.Error()})
				return err
			}
		}
	} else {
		_ = m.stopOpenVPN()
		m.emit("service.vpn.openvpn.disabled", map[string]any{})
		m.mu.Lock()
		m.ovpnLastError = ""
		m.mu.Unlock()
	}
	return nil
}

func (m *VPNManager) Validate(ctx context.Context, cfg config.VPNConfig) error {
	_ = ctx
	if !cfg.OpenVPN.Enabled {
		return nil
	}
	return m.validateOpenVPNEnabled(cfg)
}

func (m *VPNManager) validateOpenVPNEnabled(cfg config.VPNConfig) error {
	if !m.SuperviseOpenVPN {
		return errorsNew("openvpn enabled but supervision disabled (CONTAIND_SUPERVISE_OPENVPN=0)")
	}
	if m.OpenVPNPath == "" {
		return errorsNew("openvpn enabled but binary not present in the appliance image")
	}
	_, err := m.openVPNConfigPathForEnabled(cfg.OpenVPN)
	return err
}

func (m *VPNManager) Current() config.VPNConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *VPNManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"wireguard_enabled":   m.lastCfg.WireGuard.Enabled,
		"openvpn_enabled":     m.lastCfg.OpenVPN.Enabled,
		"wg_peers":            len(m.lastCfg.WireGuard.Peers),
		"last_render":         m.lastRender.Format(time.RFC3339Nano),
		"last_error":          m.lastError,
		"openvpn_installed":   m.OpenVPNPath != "",
		"openvpn_binary":      m.OpenVPNPath,
		"openvpn_supervise":   m.SuperviseOpenVPN,
		"openvpn_running":     m.ovpnRunning,
		"openvpn_pid":         pidOrZero(m.ovpnCmd),
		"openvpn_config_path": firstNonEmpty(m.ovpnConfigPath, m.lastCfg.OpenVPN.ConfigPath),
		"openvpn_last_start":  formatMaybe(m.ovpnLastStart),
		"openvpn_last_stop":   formatMaybe(m.ovpnLastStop),
		"openvpn_last_exit":   m.ovpnLastExit,
		"openvpn_last_error":  m.ovpnLastError,
		"note":                "WireGuard is applied in-engine; OpenVPN is supervised in mgmt only when enabled, installed, and configured.",
	}
}

func (m *VPNManager) startOpenVPN(configPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if configPath == "" {
		return errorsNew("openvpn configPath is empty")
	}

	if m.ovpnRunning && m.ovpnCmd != nil && m.ovpnCmd.Process != nil {
		// Restart if config path changes; OpenVPN doesn't have a safe generic reload.
		if m.ovpnConfigPath == configPath {
			return nil
		}
		_ = m.stopOpenVPNNoLock()
	}

	cmd := exec.Command(m.OpenVPNPath, "--config", configPath, "--verb", "3")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	m.ovpnCmd = cmd
	m.ovpnRunning = true
	m.ovpnConfigPath = configPath
	m.ovpnLastStart = time.Now().UTC()
	m.ovpnLastExit = ""
	m.ovpnLastError = ""
	go m.emit("service.vpn.openvpn.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath})

	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.ovpnRunning = false
		m.ovpnLastStop = time.Now().UTC()
		if err != nil {
			m.ovpnLastExit = err.Error()
		} else {
			m.ovpnLastExit = "exited"
		}
		pid := pidOrZero(cmd)
		exit := m.ovpnLastExit
		go m.emit("service.vpn.openvpn.exited", map[string]any{"pid": pid, "exit": exit})
	}()

	return nil
}

func (m *VPNManager) openVPNConfigPathForEnabled(cfg config.OpenVPNConfig) (string, error) {
	if !cfg.Enabled {
		return "", nil
	}
	mode := strings.TrimSpace(cfg.Mode)
	if mode == "" {
		mode = "client"
	}
	if mode == "server" && cfg.Server != nil {
		path, err := m.renderOpenVPNManagedServer(cfg.Server)
		if err != nil {
			return "", err
		}
		return path, nil
	}
	// Prefer managed config when present.
	if cfg.Managed != nil {
		path, err := m.renderOpenVPNManagedClient(cfg.Managed)
		if err != nil {
			return "", err
		}
		return path, nil
	}

	path := strings.TrimSpace(cfg.ConfigPath)
	if path == "" {
		return "", errorsNew("openvpn enabled but configPath is empty")
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("openvpn configPath not readable: %s", err.Error())
	}
	if err := ensureOpenVPNConfigForeground(path); err != nil {
		return "", err
	}
	return path, nil
}

func (m *VPNManager) renderOpenVPNManagedClient(mc *config.OpenVPNManagedClientConfig) (string, error) {
	if mc == nil {
		return "", errorsNew("openvpn managed config is nil")
	}
	remote := strings.TrimSpace(mc.Remote)
	if remote == "" {
		return "", errorsNew("openvpn managed remote is empty")
	}
	port := mc.Port
	if port == 0 {
		port = 1194
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("openvpn managed port invalid: %d", mc.Port)
	}
	proto := strings.ToLower(strings.TrimSpace(mc.Proto))
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		return "", fmt.Errorf("openvpn managed proto invalid: %q", mc.Proto)
	}
	if strings.TrimSpace(mc.CA) == "" || strings.TrimSpace(mc.Cert) == "" || strings.TrimSpace(mc.Key) == "" {
		return "", errorsNew("openvpn managed requires ca, cert, and key PEM blocks")
	}
	user := strings.TrimSpace(mc.Username)
	pass := strings.TrimSpace(mc.Password)
	if (user != "") != (pass != "") {
		return "", errorsNew("openvpn managed username/password must be set together")
	}

	// Use a stable location under /data so it persists across restarts.
	dir := openVPNManagedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	confPath := filepath.Join(dir, "openvpn.conf")
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	authPath := filepath.Join(dir, "auth.txt")

	if err := atomicWriteFile(caPath, []byte(strings.TrimSpace(mc.CA)+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := atomicWriteFile(certPath, []byte(strings.TrimSpace(mc.Cert)+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := atomicWriteFile(keyPath, []byte(strings.TrimSpace(mc.Key)+"\n"), 0o600); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("resolv-retry infinite\n")
	if proto == "tcp" {
		b.WriteString("proto tcp-client\n")
	} else {
		b.WriteString("proto udp\n")
	}
	b.WriteString(fmt.Sprintf("remote %s %d\n", remote, port))
	b.WriteString("ca ca.crt\n")
	b.WriteString("cert client.crt\n")
	b.WriteString("key client.key\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth-nocache\n")
	if user != "" {
		if err := atomicWriteFile(authPath, []byte(user+"\n"+pass+"\n"), 0o600); err != nil {
			return "", err
		}
		b.WriteString("auth-user-pass auth.txt\n")
	} else {
		_ = os.Remove(authPath)
	}
	b.WriteString("verb 3\n")

	if err := atomicWriteFile(confPath, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return confPath, nil
}

func (m *VPNManager) renderOpenVPNManagedServer(sc *config.OpenVPNManagedServerConfig) (string, error) {
	if sc == nil {
		return "", errorsNew("openvpn server config is nil")
	}
	port := sc.ListenPort
	if port == 0 {
		port = 1194
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("openvpn server listenPort invalid: %d", sc.ListenPort)
	}
	proto := strings.ToLower(strings.TrimSpace(sc.Proto))
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		return "", fmt.Errorf("openvpn server proto invalid: %q", sc.Proto)
	}
	tunnelCIDR := strings.TrimSpace(sc.TunnelCIDR)
	if tunnelCIDR == "" {
		return "", errorsNew("openvpn server tunnelCIDR is empty")
	}
	ip, ipnet, err := netParseCIDR4(tunnelCIDR)
	if err != nil {
		return "", fmt.Errorf("openvpn server tunnelCIDR invalid: %q", tunnelCIDR)
	}
	network := ip.Mask(ipnet.Mask).To4()
	mask := netmaskString(ipnet.Mask)
	if network == nil || mask == "" {
		return "", errorsNew("openvpn server tunnelCIDR invalid (must be IPv4 CIDR)")
	}

	dir := openVPNManagedServerDir()
	pkiDir := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return "", err
	}

	caCertPath, caKeyPath, err := EnsureOpenVPNCA(pkiDir)
	if err != nil {
		return "", err
	}
	serverCertPath, serverKeyPath, err := EnsureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("port " + fmt.Sprintf("%d", port) + "\n")
	if proto == "tcp" {
		b.WriteString("proto tcp-server\n")
	} else {
		b.WriteString("proto udp\n")
	}
	b.WriteString("dev tun\n")
	b.WriteString("topology subnet\n")
	b.WriteString(fmt.Sprintf("server %s %s\n", network.String(), mask))
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("keepalive 10 60\n")
	b.WriteString("dh none\n")
	if proto == "udp" {
		b.WriteString("explicit-exit-notify 1\n")
	}
	if sc.ClientToClient {
		b.WriteString("client-to-client\n")
	}
	b.WriteString("ca " + caCertPath + "\n")
	b.WriteString("cert " + serverCertPath + "\n")
	b.WriteString("key " + serverKeyPath + "\n")

	for _, dns := range sc.PushDNS {
		d := strings.TrimSpace(dns)
		if d == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", d))
	}
	for _, cidr := range sc.PushRoutes {
		c := strings.TrimSpace(cidr)
		if c == "" {
			continue
		}
		_, rnet, err := netParseCIDR4(c)
		if err != nil {
			return "", fmt.Errorf("openvpn server pushRoutes invalid: %q", cidr)
		}
		b.WriteString(fmt.Sprintf("push \"route %s %s\"\n", rnet.IP.String(), netmaskString(rnet.Mask)))
	}
	b.WriteString("verb 3\n")

	confPath := filepath.Join(dir, "openvpn.conf")
	if err := atomicWriteFile(confPath, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return confPath, nil
}

func openVPNManagedDir() string {
	// Prefer the same root used by profile uploads, but support the legacy env var
	// that points directly at /data/openvpn/profiles.
	base := "/data/openvpn"
	if v := strings.TrimSpace(os.Getenv("CONTAIND_OPENVPN_DIR")); v != "" {
		base = v
		if strings.HasSuffix(base, "/profiles") {
			base = filepath.Dir(base)
		}
	}
	return filepath.Join(base, "managed")
}

func openVPNManagedServerDir() string {
	return filepath.Join(openVPNManagedDir(), "server")
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (m *VPNManager) stopOpenVPN() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopOpenVPNNoLock()
}

func (m *VPNManager) stopOpenVPNNoLock() error {
	if !m.ovpnRunning || m.ovpnCmd == nil || m.ovpnCmd.Process == nil {
		m.ovpnRunning = false
		m.ovpnCmd = nil
		return nil
	}
	_ = m.ovpnCmd.Process.Signal(syscall.SIGTERM)
	go m.emit("service.vpn.openvpn.stopped", map[string]any{"pid": m.ovpnCmd.Process.Pid})
	m.ovpnRunning = false
	m.ovpnCmd = nil
	m.ovpnLastStop = time.Now().UTC()
	return nil
}

func (m *VPNManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["service"] = "vpn"
	m.OnEvent(kind, attrs)
}

func firstNonEmpty(v string, def string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func errorsNew(msg string) error { return fmt.Errorf("%s", msg) }

func ensureOpenVPNConfigForeground(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Reject configs that daemonize, because the supervisor expects a foreground process.
	lines := strings.Split(string(b), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// tokens split on whitespace
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "daemon" {
			return errorsNew("openvpn config contains 'daemon' directive; remove it (supervisor requires foreground)")
		}
	}
	return nil
}
