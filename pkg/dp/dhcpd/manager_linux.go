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
	cfg    config.DHCPConfig
	pool   pool
	start  time.Time
	retry  int
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

	OnEvent func(kind string, attrs map[string]any)
}

func NewManager() *Manager {
	return &Manager{
		listeners: map[string]listener{},
		leases:    map[string]Lease{},
		statePath: "/data/dhcp-leases.json",
	}
}

// SetOnEvent registers a callback for emitting normalized runtime/lease events.
// The callback must be non-blocking (it runs on the DHCP handler goroutine).
func (m *Manager) SetOnEvent(fn func(kind string, attrs map[string]any)) {
	if m == nil {
		return
	}
	m.OnEvent = fn
}

func (m *Manager) Apply(ctx context.Context, cfg config.DHCPConfig, ifaces []config.Interface) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastApply = time.Now().UTC()

	// Opportunistically prune expired leases on apply.
	m.pruneExpiredLeasesLocked()

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
		go m.emit("service.dhcp.disabled", map[string]any{
			"enabled": false,
		})
		return nil
	}

	// Ensure nft redirect exists for selected devs.
	if err := ensureRedirect(ctx, devs, true); err != nil {
		m.lastErr = err.Error()
		go m.emit("service.dhcp.redirect_failed", map[string]any{
			"error":   err.Error(),
			"devices": devs,
		})
		return err
	}

	// Stop listeners no longer needed.
	for dev, l := range m.listeners {
		if !contains(devs, dev) {
			l.cancel()
			delete(m.listeners, dev)
			go m.emit("service.dhcp.listener_stopped", map[string]any{"dev": dev})
		}
	}

	// Restart listeners whose scope/config changed.
	for _, dev := range devs {
		l, ok := m.listeners[dev]
		if !ok {
			continue
		}
		pl, ok := pools[dev]
		if !ok {
			continue
		}
		if dhcpListenerNeedsRestart(l, cfg, pl) {
			l.cancel()
			delete(m.listeners, dev)
			go m.emit("service.dhcp.listener_restarting", map[string]any{"dev": dev})
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
		m.startListenerLocked(dev, cfg, pl)
	}

	// Best-effort load persisted leases on first enable.
	m.loadLeasesLocked()

	m.lastErr = ""
	go m.emit("service.dhcp.applied", map[string]any{
		"enabled": true,
		"devices": devs,
		"pools":   len(pools),
	})
	return nil
}

func dhcpListenerNeedsRestart(l listener, cfg config.DHCPConfig, pl pool) bool {
	// Note: we only compare fields that affect on-wire behavior.
	if l.pool.Start == nil || l.pool.End == nil || pl.Start == nil || pl.End == nil {
		return true
	}
	if !l.pool.Start.Equal(pl.Start) || !l.pool.End.Equal(pl.End) {
		return true
	}
	if strings.TrimSpace(l.cfg.Router) != strings.TrimSpace(cfg.Router) {
		return true
	}
	if strings.TrimSpace(l.cfg.Domain) != strings.TrimSpace(cfg.Domain) {
		return true
	}
	if parseLeaseSeconds(l.cfg.LeaseSeconds) != parseLeaseSeconds(cfg.LeaseSeconds) {
		return true
	}
	if !sameStringSet(l.cfg.DNSServers, cfg.DNSServers) {
		return true
	}
	return false
}

func sameStringSet(a, b []string) bool {
	am := map[string]struct{}{}
	for _, s := range a {
		if v := strings.TrimSpace(s); v != "" {
			am[v] = struct{}{}
		}
	}
	bm := map[string]struct{}{}
	for _, s := range b {
		if v := strings.TrimSpace(s); v != "" {
			bm[v] = struct{}{}
		}
	}
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			return false
		}
	}
	return true
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	devs := make([]map[string]any, 0, len(m.listeners))
	for dev, l := range m.listeners {
		devs = append(devs, map[string]any{
			"dev":        dev,
			"started_at": l.start.UTC().Format(time.RFC3339Nano),
			"retry":      l.retry,
		})
	}
	sort.Slice(devs, func(i, j int) bool { return fmt.Sprint(devs[i]["dev"]) < fmt.Sprint(devs[j]["dev"]) })
	return map[string]any{
		"enabled":        len(m.listeners) > 0,
		"listen_devices": len(m.listeners),
		"devices":        devs,
		"leases":         len(m.leases),
		"last_apply":     m.lastApply.Format(time.RFC3339Nano),
		"last_error":     m.lastErr,
		"note":           "DHCP server is minimal (IPv4 only; no conflict detection). It runs per-interface listeners and persists leases to /data.",
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
	prev, hadPrev := m.leases[key]
	m.leases[key] = Lease{
		Iface:     dev,
		MAC:       mac,
		IP:        ip,
		ExpiresAt: exp,
		Hostname:  hostname,
	}
	m.persistLeasesLocked()
	action := "assigned"
	if hadPrev && prev.IP == ip {
		action = "renewed"
	}
	go m.emit("service.dhcp.lease."+action, map[string]any{
		"dev":        dev,
		"mac":        mac,
		"ip":         ip,
		"hostname":   hostname,
		"expires_at": exp,
	})
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

func (m *Manager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["component"] = "dhcpd"
	m.OnEvent(kind, attrs)
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
		m.lastErr = "lease load failed: " + err.Error()
		go m.emit("service.dhcp.lease_load_failed", map[string]any{"error": err.Error()})
		return
	}
	for _, l := range ls {
		if strings.TrimSpace(l.Iface) == "" || strings.TrimSpace(l.MAC) == "" || strings.TrimSpace(l.IP) == "" {
			continue
		}
		// Filter expired on load.
		if t, err := time.Parse(time.RFC3339Nano, l.ExpiresAt); err == nil && time.Now().UTC().After(t) {
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
	now := time.Now().UTC()
	for k, l := range m.leases {
		if t, err := time.Parse(time.RFC3339Nano, l.ExpiresAt); err == nil && now.After(t) {
			delete(m.leases, k)
			continue
		}
		ls = append(ls, l)
	}
	b, _ := json.MarshalIndent(ls, "", "  ")
	tmp := m.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		m.lastErr = "lease persist failed: " + err.Error()
		go m.emit("service.dhcp.lease_persist_failed", map[string]any{"error": err.Error()})
		return
	}
	if err := os.Rename(tmp, m.statePath); err != nil {
		m.lastErr = "lease persist failed: " + err.Error()
		go m.emit("service.dhcp.lease_persist_failed", map[string]any{"error": err.Error()})
		_ = os.Remove(tmp)
		return
	}
}

func (m *Manager) startListenerLocked(dev string, cfg config.DHCPConfig, pl pool) {
	lctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func(dev string, pl pool) {
		errCh <- serveDHCPv4(lctx, dev, cfg, pl, m)
	}(dev, pl)
	m.listeners[dev] = listener{
		cancel: cancel,
		errCh:  errCh,
		cfg:    cfg,
		pool:   pl,
		start:  time.Now().UTC(),
		retry:  0,
	}
	go m.emit("service.dhcp.listener_started", map[string]any{"dev": dev})

	// Monitor exit and restart with backoff (best-effort).
	go func(dev string) {
		err := <-errCh
		if err == nil || errors.Is(err, context.Canceled) {
			return
		}
		m.handleListenerExit(dev, err)
	}(dev)
}

func (m *Manager) handleListenerExit(dev string, err error) {
	m.mu.Lock()
	l, ok := m.listeners[dev]
	if !ok {
		m.mu.Unlock()
		return
	}
	// Listener exited unexpectedly; clear it so we can restart.
	delete(m.listeners, dev)
	l.retry++
	m.lastErr = fmt.Sprintf("listener %s failed: %v", dev, err)
	cfg := l.cfg
	pl := l.pool
	m.mu.Unlock()

	go m.emit("service.dhcp.listener_failed", map[string]any{
		"dev":   dev,
		"error": err.Error(),
	})

	// Backoff restart: 250ms, 500ms, 1s, 2s, 4s (cap).
	backoff := 250 * time.Millisecond
	for i := 0; i < l.retry && backoff < 4*time.Second; i++ {
		backoff *= 2
		if backoff > 4*time.Second {
			backoff = 4 * time.Second
		}
	}
	time.Sleep(backoff)

	m.mu.Lock()
	// Only restart if DHCP is still enabled and this dev is still desired.
	if !cfg.Enabled || containsListener(m.listeners, dev) {
		m.mu.Unlock()
		return
	}
	m.startListenerLocked(dev, cfg, pl)
	// Carry retry count forward (so repeated failures back off).
	nl := m.listeners[dev]
	nl.retry = l.retry
	m.listeners[dev] = nl
	m.mu.Unlock()
	go m.emit("service.dhcp.listener_restarted", map[string]any{"dev": dev, "retry": l.retry})
}

func containsListener(listeners map[string]listener, dev string) bool {
	_, ok := listeners[dev]
	return ok
}

func (m *Manager) pruneExpiredLeasesLocked() {
	now := time.Now().UTC()
	for k, l := range m.leases {
		t, err := time.Parse(time.RFC3339Nano, l.ExpiresAt)
		if err == nil && now.After(t) {
			delete(m.leases, k)
		}
	}
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
