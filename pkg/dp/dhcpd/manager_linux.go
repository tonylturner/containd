//go:build linux

package dhcpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

// Lease represents a DHCPv4 lease handed out by the embedded DHCP server.
type Lease struct {
	Iface     string `json:"iface"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	ExpiresAt string `json:"expiresAt"`
	Hostname  string `json:"hostname,omitempty"`
}

type pool struct {
	Start net.IP
	End   net.IP
}

type listener struct {
	cancel context.CancelFunc
	errCh  chan error
}

// Manager runs a minimal DHCPv4 server on configured interfaces.
// It is designed for lab/early appliance workflows and intentionally limited:
// - IPv4 only
// - Broadcast replies only
// - No conflict detection, no authoritative NAK behavior yet
// - Leases are in-memory with best-effort persistence to `/data/dhcp-leases.json`
//
// Because the engine runs as non-root, the manager installs a small nftables redirect
// for UDP/67 -> UDP/1067 (unprivileged) for the configured interfaces.
type Manager struct {
	mu sync.Mutex

	listeners map[string]listener // dev -> listener
	leases    map[string]Lease    // key=dev|mac
	lastErr   string
	lastApply time.Time

	statePath string
}

func NewManager() *Manager {
	return &Manager{
		listeners: map[string]listener{},
		leases:    map[string]Lease{},
		statePath: "/data/dhcp-leases.json",
	}
}

func (m *Manager) Apply(ctx context.Context, cfg config.DHCPConfig, ifaces []config.Interface) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastApply = time.Now().UTC()

	// Resolve logical interface names to kernel devices.
	byName := map[string]config.Interface{}
	for _, i := range ifaces {
		if strings.TrimSpace(i.Name) != "" {
			byName[i.Name] = i
		}
	}
	resolveDev := func(ref string) string {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return ""
		}
		if i, ok := byName[ref]; ok {
			if d := strings.TrimSpace(i.Device); d != "" {
				return d
			}
			return strings.TrimSpace(i.Name)
		}
		return ref
	}

	// Build pool map keyed by resolved device.
	pools := map[string]pool{}
	for _, p := range cfg.Pools {
		dev := resolveDev(p.Iface)
		if dev == "" {
			continue
		}
		start := net.ParseIP(strings.TrimSpace(p.Start)).To4()
		end := net.ParseIP(strings.TrimSpace(p.End)).To4()
		if start == nil || end == nil {
			return fmt.Errorf("dhcp: invalid pool %q: %s-%s", p.Iface, p.Start, p.End)
		}
		pools[dev] = pool{Start: start, End: end}
	}

	// Determine the set of devices to serve on.
	var devs []string
	for _, li := range cfg.ListenIfaces {
		dev := resolveDev(li)
		if dev == "" {
			continue
		}
		devs = append(devs, dev)
	}
	sort.Strings(devs)
	devs = compactStrings(devs)

	// Stop everything if disabled.
	if !cfg.Enabled || len(devs) == 0 {
		for dev, l := range m.listeners {
			l.cancel()
			delete(m.listeners, dev)
		}
		_ = ensureRedirect(ctx, nil, false)
		m.lastErr = ""
		return nil
	}

	// Ensure nft redirect exists for selected devs.
	if err := ensureRedirect(ctx, devs, true); err != nil {
		m.lastErr = err.Error()
		return err
	}

	// Stop listeners no longer needed.
	for dev, l := range m.listeners {
		if !contains(devs, dev) {
			l.cancel()
			delete(m.listeners, dev)
		}
	}

	// Start new listeners.
	for _, dev := range devs {
		if _, ok := m.listeners[dev]; ok {
			continue
		}
		pl, ok := pools[dev]
		if !ok {
			return fmt.Errorf("dhcp: no pool configured for %s", dev)
		}
		lctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func(dev string, pl pool) {
			errCh <- serveDHCPv4(lctx, dev, cfg, pl, m)
		}(dev, pl)
		m.listeners[dev] = listener{cancel: cancel, errCh: errCh}
	}

	// Best-effort load persisted leases on first enable.
	m.loadLeasesLocked()

	m.lastErr = ""
	return nil
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"enabled":        len(m.listeners) > 0,
		"listen_devices": len(m.listeners),
		"leases":         len(m.leases),
		"last_apply":     m.lastApply.Format(time.RFC3339Nano),
		"last_error":     m.lastErr,
		"note":           "DHCP server is minimal (IPv4 only; no conflict detection).",
	}
}

func (m *Manager) Leases() []Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	out := make([]Lease, 0, len(m.leases))
	for _, l := range m.leases {
		// Filter expired.
		if t, err := time.Parse(time.RFC3339Nano, l.ExpiresAt); err == nil && now.After(t) {
			continue
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Iface != out[j].Iface {
			return out[i].Iface < out[j].Iface
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func (m *Manager) upsertLease(dev, mac, ip, hostname string, leaseSeconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if leaseSeconds <= 0 {
		leaseSeconds = 3600
	}
	exp := time.Now().UTC().Add(time.Duration(leaseSeconds) * time.Second).Format(time.RFC3339Nano)
	key := dev + "|" + mac
	m.leases[key] = Lease{
		Iface:     dev,
		MAC:       mac,
		IP:        ip,
		ExpiresAt: exp,
		Hostname:  hostname,
	}
	m.persistLeasesLocked()
}

func (m *Manager) lookupLeaseIP(dev, mac string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := dev + "|" + mac
	l, ok := m.leases[key]
	if !ok {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, l.ExpiresAt)
	if err == nil && time.Now().UTC().After(t) {
		delete(m.leases, key)
		m.persistLeasesLocked()
		return "", false
	}
	return l.IP, true
}

func (m *Manager) isIPInUse(dev, ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.leases {
		if l.Iface != dev || l.IP != ip {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, l.ExpiresAt)
		if err == nil && time.Now().UTC().After(t) {
			continue
		}
		return true
	}
	return false
}

func (m *Manager) loadLeasesLocked() {
	if m.statePath == "" {
		return
	}
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		return
	}
	var ls []Lease
	if err := json.Unmarshal(b, &ls); err != nil {
		return
	}
	for _, l := range ls {
		if strings.TrimSpace(l.Iface) == "" || strings.TrimSpace(l.MAC) == "" || strings.TrimSpace(l.IP) == "" {
			continue
		}
		m.leases[l.Iface+"|"+l.MAC] = l
	}
}

func (m *Manager) persistLeasesLocked() {
	if m.statePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.statePath), 0o755)
	var ls []Lease
	for _, l := range m.leases {
		ls = append(ls, l)
	}
	b, _ := json.MarshalIndent(ls, "", "  ")
	_ = os.WriteFile(m.statePath, b, 0o600)
}

func ensureRedirect(ctx context.Context, devs []string, enabled bool) error {
	// If `nft` isn't present, fail softly: DHCPd may still work if running as root with NET_BIND_SERVICE,
	// but in our default nonroot engine image we rely on redirect.
	if _, err := exec.LookPath("nft"); err != nil {
		if enabled {
			return fmt.Errorf("dhcp: nft not found (required for UDP/67 redirect): %w", err)
		}
		return nil
	}

	if !enabled {
		cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "containd_dhcp")
		_ = cmd.Run()
		return nil
	}

	var b strings.Builder
	b.WriteString("table inet containd_dhcp {\n")
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority -100; policy accept;\n")
	for _, dev := range devs {
		b.WriteString("    iifname \"")
		b.WriteString(dev)
		b.WriteString("\" udp dport 67 redirect to :1067\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")

	// Replace the table atomically.
	script := "delete table inet containd_dhcp\n" + b.String()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dhcp: nft apply failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func compactStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	var last string
	for _, s := range in {
		if s == "" || s == last {
			continue
		}
		out = append(out, s)
		last = s
	}
	return out
}

func parseLeaseSeconds(v int) int {
	if v <= 0 {
		return 3600
	}
	if v > 7*24*3600 {
		// Avoid absurd defaults in early phases.
		return 7 * 24 * 3600
	}
	return v
}

func parseIPv4List(list []string) []net.IP {
	var out []net.IP
	for _, s := range list {
		ip := net.ParseIP(strings.TrimSpace(s)).To4()
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func ipToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func nextFreeIP(dev string, pl pool, m *Manager) (net.IP, error) {
	start := ipToU32(pl.Start)
	end := ipToU32(pl.End)
	if start == 0 || end == 0 || end < start {
		return nil, errors.New("invalid pool range")
	}
	for v := start; v <= end; v++ {
		ip := u32ToIP(v)
		if !m.isIPInUse(dev, ip.String()) {
			return ip, nil
		}
	}
	return nil, errors.New("no free leases available")
}

func mustIPv4(ip net.IP) (net.IP, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("expected IPv4")
	}
	return ip4, nil
}

func parsePort(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, _ := strconv.Atoi(s)
	return v
}

