package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

const defaultDir = "/data/pcaps"

type Manager struct {
	mu      sync.Mutex
	dir     string
	cfg     config.PCAPConfig
	running bool
	started time.Time
	lastErr string
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	workers map[string]*worker
}

func NewManager(dir string) *Manager {
	if dir == "" {
		dir = defaultDir
	}
	return &Manager{dir: dir}
}

func (m *Manager) Configure(cfg config.PCAPConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = normalizeConfig(cfg)
	return nil
}

func (m *Manager) Config() config.PCAPConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

func (m *Manager) Start(ctx context.Context, cfg config.PCAPConfig) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("pcap capture already running")
	}
	cfg = normalizeConfig(cfg)
	if len(cfg.Interfaces) == 0 {
		m.mu.Unlock()
		return errors.New("pcap requires at least one interface")
	}
	m.cfg = cfg
	m.lastErr = ""
	m.started = time.Now().UTC()
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.running = true
	m.workers = make(map[string]*worker)
	m.mu.Unlock()

	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		m.setError(err)
		m.Stop()
		return err
	}

	ifaces := uniqueStrings(cfg.Interfaces)
	for _, iface := range ifaces {
		w := newWorker(m.dir, iface, cfg)
		m.mu.Lock()
		m.workers[iface] = w
		m.mu.Unlock()
		m.wg.Add(1)
		go func(w *worker) {
			defer m.wg.Done()
			if err := w.run(runCtx, m); err != nil {
				m.setError(err)
			}
		}(w)
	}

	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	cancel := m.cancel
	m.running = false
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	return nil
}

func (m *Manager) requestStop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	cancel := m.cancel
	m.running = false
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	ifaces := make([]string, 0, len(m.workers))
	for k := range m.workers {
		ifaces = append(ifaces, k)
	}
	sort.Strings(ifaces)
	return Status{
		Running:    m.running,
		Interfaces: ifaces,
		StartedAt:  m.started,
		LastError:  m.lastErr,
	}
}

func (m *Manager) List() ([]Item, error) {
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pcap") {
			continue
		}
		path := filepath.Join(m.dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		meta, _ := readMeta(metaPath(path))
		iface := meta.Interface
		if iface == "" {
			iface = inferInterface(entry.Name())
		}
		item := Item{
			Name:      entry.Name(),
			Interface: iface,
			SizeBytes: info.Size(),
			CreatedAt: meta.CreatedAt,
			Tags:      meta.Tags,
			Status:    meta.Status,
		}
		if item.CreatedAt.IsZero() {
			item.CreatedAt = info.ModTime()
		}
		if item.Status == "" {
			item.Status = "ready"
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items, nil
}

func inferInterface(name string) string {
	parts := strings.Split(name, "_")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func (m *Manager) Delete(name string) error {
	path, err := m.safePath(name)
	if err != nil {
		return err
	}
	_ = os.Remove(metaPath(path))
	return os.Remove(path)
}

func (m *Manager) Tag(name string, tags []string) error {
	path, err := m.safePath(name)
	if err != nil {
		return err
	}
	meta, _ := readMeta(metaPath(path))
	meta.Name = name
	meta.Tags = uniqueStrings(tags)
	return writeMeta(metaPath(path), meta)
}

func (m *Manager) Upload(name string, r io.Reader) (Item, error) {
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return Item{}, err
	}
	base := sanitizeUploadName(name)
	if base == "" {
		base = fmt.Sprintf("upload_%s.pcap", time.Now().UTC().Format("20060102_150405"))
	}
	if !strings.HasSuffix(strings.ToLower(base), ".pcap") {
		base += ".pcap"
	}
	path := uniquePath(filepath.Join(m.dir, base))
	f, err := os.Create(path)
	if err != nil {
		return Item{}, err
	}
	defer f.Close()
	n, err := io.Copy(f, r)
	if err != nil {
		return Item{}, err
	}
	meta := Meta{
		Name:      filepath.Base(path),
		Interface: "",
		CreatedAt: time.Now().UTC(),
		Tags:      []string{},
		Status:    "ready",
	}
	_ = writeMeta(metaPath(path), meta)
	item := Item{
		Name:      meta.Name,
		Interface: meta.Interface,
		SizeBytes: n,
		CreatedAt: meta.CreatedAt,
		Tags:      meta.Tags,
		Status:    meta.Status,
	}
	return item, nil
}

func (m *Manager) Open(name string) (io.ReadCloser, int64, error) {
	path, err := m.safePath(name)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

func (m *Manager) Replay(ctx context.Context, req ReplayRequest) error {
	path, err := m.safePath(req.Name)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(req.Interface)
	if err != nil {
		return fmt.Errorf("unknown interface %q: %w", req.Interface, err)
	}
	return replayFile(ctx, path, iface, req.RatePPS)
}

func (m *Manager) safePath(name string) (string, error) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || strings.Contains(base, "..") || !strings.HasSuffix(base, ".pcap") {
		return "", fmt.Errorf("invalid pcap name")
	}
	path := filepath.Join(m.dir, base)
	return path, nil
}

func (m *Manager) setError(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = err.Error()
}

func normalizeConfig(cfg config.PCAPConfig) config.PCAPConfig {
	if cfg.Snaplen == 0 {
		cfg.Snaplen = 262144
	}
	if cfg.MaxSizeMB == 0 {
		cfg.MaxSizeMB = 64
	}
	if cfg.MaxFiles == 0 {
		cfg.MaxFiles = 8
	}
	if cfg.BufferMB == 0 {
		cfg.BufferMB = 4
	}
	if cfg.RotateSeconds == 0 {
		cfg.RotateSeconds = 300
	}
	if cfg.FilePrefix == "" {
		cfg.FilePrefix = "capture"
	}
	if cfg.Mode == "" {
		cfg.Mode = "rolling"
	}
	if cfg.Filter.Proto == "" {
		cfg.Filter.Proto = "any"
	}
	return cfg
}

func uniqueStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func sanitizeUploadName(name string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return strings.Trim(strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, base), "._")
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); err != nil {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; i < 10000; i++ {
		candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(candidate); err != nil {
			return candidate
		}
	}
	ts := time.Now().UTC().Format("20060102_150405")
	return fmt.Sprintf("%s_%s%s", base, ts, ext)
}
