// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
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
	ovpnWaitCh     chan struct{}
	ovpnRunning    bool
	ovpnConfigPath string
	ovpnLastStart  time.Time
	ovpnLastStop   time.Time
	ovpnLastExit   string
	ovpnLastError  string
	log            *zap.SugaredLogger
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
	return &VPNManager{
		BaseDir:          baseDir,
		SuperviseOpenVPN: supervise,
		OpenVPNPath:      openvpnPath,
		log:              newVPNLogger(),
	}
}

func newVPNLogger() *zap.SugaredLogger {
	lg, err := commonlog.NewZap("vpn", "vpn", commonlog.Options{
		FilePath: "/data/logs/vpn.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		return zap.NewNop().Sugar()
	}
	return lg
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
		m.log.Errorw("failed to render vpn config", "error", err)
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		m.log.Errorw("failed to write vpn config", "path", path, "error", err)
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
	m.log.Infow("rendered vpn config", "path", path)

	// OpenVPN supervision (optional)
	if cfg.OpenVPN.Enabled {
		configPath, err := m.openVPNConfigPathForEnabled(cfg.OpenVPN)
		if err != nil {
			m.mu.Lock()
			m.ovpnLastError = err.Error()
			m.mu.Unlock()
			m.emit("service.vpn.openvpn.invalid", map[string]any{"error": err.Error()})
			m.log.Errorw("openvpn config invalid", "error", err)
			return err
		}
		if m.SuperviseOpenVPN && m.OpenVPNPath != "" {
			if err := m.startOpenVPN(configPath); err != nil {
				m.mu.Lock()
				m.ovpnLastError = err.Error()
				m.mu.Unlock()
				m.emit("service.vpn.openvpn.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
				m.log.Errorw("failed to start openvpn", "error", err)
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
		"openvpn_mode":        strings.TrimSpace(m.lastCfg.OpenVPN.Mode),
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
		"openvpn_server_tunnel": func() string {
			if m.lastCfg.OpenVPN.Server == nil {
				return ""
			}
			return strings.TrimSpace(m.lastCfg.OpenVPN.Server.TunnelCIDR)
		}(),
		"openvpn_server_endpoint": func() string {
			if m.lastCfg.OpenVPN.Server == nil {
				return ""
			}
			return strings.TrimSpace(m.lastCfg.OpenVPN.Server.PublicEndpoint)
		}(),
		"note": "WireGuard is applied in-engine; OpenVPN is supervised in mgmt only when enabled, installed, and configured.",
	}
}

func (m *VPNManager) startOpenVPN(configPath string) error {
	if configPath == "" {
		return errorsNew("openvpn configPath is empty")
	}

	m.mu.Lock()
	if m.ovpnRunning && m.ovpnCmd != nil && m.ovpnCmd.Process != nil {
		// Restart if config path changes; OpenVPN doesn't have a safe generic reload.
		if m.ovpnConfigPath == configPath {
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
		if err := m.stopOpenVPN(); err != nil {
			return err
		}
		m.mu.Lock()
	}

	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(m.OpenVPNPath, "--config", configPath, "--verb", "3")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return err
	}
	waitCh := make(chan struct{})
	m.ovpnCmd = cmd
	m.ovpnWaitCh = waitCh
	m.ovpnRunning = true
	m.ovpnConfigPath = configPath
	m.ovpnLastStart = time.Now().UTC()
	m.ovpnLastExit = ""
	m.ovpnLastError = ""
	m.mu.Unlock()
	m.log.Infow("started openvpn", "pid", cmd.Process.Pid, "config", configPath)
	go m.emit("service.vpn.openvpn.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})

	go m.waitOpenVPN(cmd, waitCh)

	return nil
}

func (m *VPNManager) waitOpenVPN(cmd *exec.Cmd, waitCh chan struct{}) {
	defer close(waitCh)

	err := cmd.Wait()
	pid := pidOrZero(cmd)
	exit := "exited"
	if err != nil {
		exit = err.Error()
	}

	m.mu.Lock()
	if m.ovpnCmd == cmd {
		m.ovpnRunning = false
		m.ovpnCmd = nil
		m.ovpnWaitCh = nil
		m.ovpnLastStop = time.Now().UTC()
		m.ovpnLastExit = exit
	}
	m.mu.Unlock()

	m.log.Infow("openvpn exited", "pid", pid, "exit", exit)
	go m.emit("service.vpn.openvpn.exited", map[string]any{"pid": pid, "exit": exit, "error_count": 1})
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
		return "", fmt.Errorf("openvpn configPath not readable: %w", err)
	}
	if err := ensureOpenVPNConfigForeground(path); err != nil {
		return "", err
	}
	return path, nil
}

func (m *VPNManager) renderOpenVPNManagedClient(mc *config.OpenVPNManagedClientConfig) (string, error) {
	opts, err := validateOpenVPNManagedClient(mc)
	if err != nil {
		return "", err
	}

	dir, err := prepareOpenVPNManagedDir()
	if err != nil {
		return "", err
	}
	confPath := filepath.Join(dir, "openvpn.conf")
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	authPath := filepath.Join(dir, "auth.txt")

	if err := writeOpenVPNManagedClientFiles(opts, caPath, certPath, keyPath); err != nil {
		return "", err
	}
	if err := writeOpenVPNManagedClientAuth(opts, authPath); err != nil {
		return "", err
	}
	if err := atomicWriteFile(confPath, []byte(renderOpenVPNManagedClientConfig(opts)), 0o600); err != nil {
		return "", err
	}
	return confPath, nil
}

func (m *VPNManager) renderOpenVPNManagedServer(sc *config.OpenVPNManagedServerConfig) (string, error) {
	opts, err := validateOpenVPNManagedServer(sc)
	if err != nil {
		return "", err
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

	confPath := filepath.Join(dir, "openvpn.conf")
	if err := atomicWriteFile(confPath, []byte(renderOpenVPNManagedServerConfig(opts, caCertPath, serverCertPath, serverKeyPath)), 0o600); err != nil {
		return "", err
	}
	return confPath, nil
}

type openVPNManagedClientOptions struct {
	remote string
	port   int
	proto  string
	ca     string
	cert   string
	key    string
	user   string
	pass   string
}

func validateOpenVPNManagedClient(mc *config.OpenVPNManagedClientConfig) (openVPNManagedClientOptions, error) {
	if mc == nil {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed config is nil")
	}
	remote := strings.TrimSpace(mc.Remote)
	if remote == "" {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed remote is empty")
	}
	port := firstNonZeroPort(mc.Port, 1194)
	if err := validateOpenVPNPort("openvpn managed port", mc.Port, port); err != nil {
		return openVPNManagedClientOptions{}, err
	}
	proto, err := validateOpenVPNProto("openvpn managed proto", mc.Proto)
	if err != nil {
		return openVPNManagedClientOptions{}, err
	}
	if strings.TrimSpace(mc.CA) == "" || strings.TrimSpace(mc.Cert) == "" || strings.TrimSpace(mc.Key) == "" {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed requires ca, cert, and key PEM blocks")
	}
	user := strings.TrimSpace(mc.Username)
	pass := strings.TrimSpace(mc.Password)
	if (user != "") != (pass != "") {
		return openVPNManagedClientOptions{}, errorsNew("openvpn managed username/password must be set together")
	}
	return openVPNManagedClientOptions{
		remote: remote,
		port:   port,
		proto:  proto,
		ca:     strings.TrimSpace(mc.CA),
		cert:   strings.TrimSpace(mc.Cert),
		key:    strings.TrimSpace(mc.Key),
		user:   user,
		pass:   pass,
	}, nil
}

func prepareOpenVPNManagedDir() (string, error) {
	dir := openVPNManagedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func writeOpenVPNManagedClientFiles(opts openVPNManagedClientOptions, caPath, certPath, keyPath string) error {
	if err := atomicWriteFile(caPath, []byte(opts.ca+"\n"), 0o600); err != nil {
		return err
	}
	if err := atomicWriteFile(certPath, []byte(opts.cert+"\n"), 0o600); err != nil {
		return err
	}
	return atomicWriteFile(keyPath, []byte(opts.key+"\n"), 0o600)
}

func writeOpenVPNManagedClientAuth(opts openVPNManagedClientOptions, authPath string) error {
	if opts.user == "" {
		_ = os.Remove(authPath)
		return nil
	}
	return atomicWriteFile(authPath, []byte(opts.user+"\n"+opts.pass+"\n"), 0o600)
}

func renderOpenVPNManagedClientConfig(opts openVPNManagedClientOptions) string {
	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("resolv-retry infinite\n")
	if opts.proto == "tcp" {
		b.WriteString("proto tcp-client\n")
	} else {
		b.WriteString("proto udp\n")
	}
	b.WriteString(fmt.Sprintf("remote %s %d\n", opts.remote, opts.port))
	b.WriteString("ca ca.crt\n")
	b.WriteString("cert client.crt\n")
	b.WriteString("key client.key\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("auth-nocache\n")
	if opts.user != "" {
		b.WriteString("auth-user-pass auth.txt\n")
	}
	b.WriteString("verb 3\n")
	return b.String()
}

type openVPNManagedServerOptions struct {
	port           int
	proto          string
	network        net.IP
	mask           string
	clientToClient bool
	pushDNS        []string
	pushRoutes     []string
}

func validateOpenVPNManagedServer(sc *config.OpenVPNManagedServerConfig) (openVPNManagedServerOptions, error) {
	if sc == nil {
		return openVPNManagedServerOptions{}, errorsNew("openvpn server config is nil")
	}
	port := firstNonZeroPort(sc.ListenPort, 1194)
	if err := validateOpenVPNPort("openvpn server listenPort", sc.ListenPort, port); err != nil {
		return openVPNManagedServerOptions{}, err
	}
	proto, err := validateOpenVPNProto("openvpn server proto", sc.Proto)
	if err != nil {
		return openVPNManagedServerOptions{}, err
	}
	network, mask, err := validateOpenVPNTunnelCIDR(sc.TunnelCIDR)
	if err != nil {
		return openVPNManagedServerOptions{}, err
	}
	pushRoutes, err := validateOpenVPNPushRoutes(sc.PushRoutes)
	if err != nil {
		return openVPNManagedServerOptions{}, err
	}
	return openVPNManagedServerOptions{
		port:           port,
		proto:          proto,
		network:        network,
		mask:           mask,
		clientToClient: sc.ClientToClient,
		pushDNS:        trimNonEmptyStrings(sc.PushDNS),
		pushRoutes:     pushRoutes,
	}, nil
}

func firstNonZeroPort(port, def int) int {
	if port == 0 {
		return def
	}
	return port
}

func validateOpenVPNPort(label string, raw, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s invalid: %d", label, raw)
	}
	return nil
}

func validateOpenVPNProto(label, raw string) (string, error) {
	proto := strings.ToLower(strings.TrimSpace(raw))
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		return "", fmt.Errorf("%s invalid: %q", label, raw)
	}
	return proto, nil
}

func validateOpenVPNTunnelCIDR(raw string) (net.IP, string, error) {
	tunnelCIDR := strings.TrimSpace(raw)
	if tunnelCIDR == "" {
		return nil, "", errorsNew("openvpn server tunnelCIDR is empty")
	}
	ip, ipnet, err := netParseCIDR4(tunnelCIDR)
	if err != nil {
		return nil, "", fmt.Errorf("openvpn server tunnelCIDR invalid: %q", tunnelCIDR)
	}
	network := ip.Mask(ipnet.Mask).To4()
	mask := netmaskString(ipnet.Mask)
	if network == nil || mask == "" {
		return nil, "", errorsNew("openvpn server tunnelCIDR invalid (must be IPv4 CIDR)")
	}
	return network, mask, nil
}

func validateOpenVPNPushRoutes(routes []string) ([]string, error) {
	validated := make([]string, 0, len(routes))
	for _, cidr := range trimNonEmptyStrings(routes) {
		if _, _, err := netParseCIDR4(cidr); err != nil {
			return nil, fmt.Errorf("openvpn server pushRoutes invalid: %q", cidr)
		}
		validated = append(validated, cidr)
	}
	return validated, nil
}

func trimNonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func renderOpenVPNManagedServerConfig(opts openVPNManagedServerOptions, caCertPath, serverCertPath, serverKeyPath string) string {
	var b strings.Builder
	b.WriteString("port " + fmt.Sprintf("%d", opts.port) + "\n")
	if opts.proto == "tcp" {
		b.WriteString("proto tcp-server\n")
	} else {
		b.WriteString("proto udp\n")
	}
	b.WriteString("dev tun\n")
	b.WriteString("topology subnet\n")
	b.WriteString(fmt.Sprintf("server %s %s\n", opts.network.String(), opts.mask))
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("keepalive 10 60\n")
	b.WriteString("dh none\n")
	if opts.proto == "udp" {
		b.WriteString("explicit-exit-notify 1\n")
	}
	if opts.clientToClient {
		b.WriteString("client-to-client\n")
	}
	b.WriteString("ca " + caCertPath + "\n")
	b.WriteString("cert " + serverCertPath + "\n")
	b.WriteString("key " + serverKeyPath + "\n")
	for _, dns := range opts.pushDNS {
		b.WriteString(fmt.Sprintf("push \"dhcp-option DNS %s\"\n", dns))
	}
	for _, cidr := range opts.pushRoutes {
		_, rnet, _ := netParseCIDR4(cidr)
		b.WriteString(fmt.Sprintf("push \"route %s %s\"\n", rnet.IP.String(), netmaskString(rnet.Mask)))
	}
	b.WriteString("verb 3\n")
	return b.String()
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
	if !m.ovpnRunning || m.ovpnCmd == nil || m.ovpnCmd.Process == nil {
		m.ovpnRunning = false
		m.ovpnCmd = nil
		m.ovpnWaitCh = nil
		m.mu.Unlock()
		return nil
	}
	cmd := m.ovpnCmd
	waitCh := m.ovpnWaitCh
	pid := cmd.Process.Pid
	m.mu.Unlock()

	_ = cmd.Process.Signal(syscall.SIGTERM)
	m.log.Infow("stopping openvpn", "pid", pid)
	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-waitCh
	}

	m.mu.Lock()
	if m.ovpnCmd == nil {
		m.ovpnLastExit = "stopped"
	}
	m.mu.Unlock()

	m.log.Infow("stopped openvpn", "pid", pid)
	go m.emit("service.vpn.openvpn.stopped", map[string]any{"pid": pid, "count": 1})
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
