package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
)

// defaultServicesDir must be writable in the single-container appliance image.
// In docker-compose we mount a persistent volume at /data.
const defaultServicesDir = "/data/services"

const defaultCertsDir = "/data/certs"

type ProxyOptions struct {
	BaseDir   string
	Supervise bool
	EnvoyPath string
	NginxPath string
	OnEvent   func(kind string, attrs map[string]any)
}

// ProxyManager renders Envoy (forward) and Nginx (reverse) configs from persistent models.
// If Supervise is enabled and binaries exist, it will also start/stop them.
type ProxyManager struct {
	BaseDir   string
	Supervise bool
	EnvoyPath string
	NginxPath string
	CertsDir  string

	OnEvent func(kind string, attrs map[string]any)

	mu             sync.Mutex
	lastCfg        config.ProxyConfig
	envoyCmd       *exec.Cmd
	nginxCmd       *exec.Cmd
	lastEnvoyError string
	lastNginxError string
	lastEnvoyStart time.Time
	lastNginxStart time.Time
	lastRender     time.Time
	logger         *log.Logger
}

func NewProxyManager(opts ProxyOptions) *ProxyManager {
	baseDir := opts.BaseDir
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	certsDir := strings.TrimSpace(os.Getenv("CONTAIND_CERTS_DIR"))
	if certsDir == "" {
		certsDir = defaultCertsDir
	}
	envoyPath := opts.EnvoyPath
	if envoyPath == "" {
		envoyPath = "/usr/bin/envoy"
	}
	nginxPath := opts.NginxPath
	if nginxPath == "" {
		nginxPath = "/usr/sbin/nginx"
	}
	return &ProxyManager{
		BaseDir:   baseDir,
		Supervise: opts.Supervise,
		EnvoyPath: envoyPath,
		NginxPath: nginxPath,
		CertsDir:  certsDir,
		logger:    logging.New("[services/proxy]"),
		OnEvent:   opts.OnEvent,
	}
}

func (m *ProxyManager) Apply(ctx context.Context, cfg config.ProxyConfig) error {
	m.mu.Lock()
	m.lastCfg = cfg
	m.mu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	if err := m.renderForward(cfg.Forward); err != nil {
		return err
	}
	if err := m.renderReverse(cfg.Reverse); err != nil {
		return err
	}
	if err := m.validateForward(ctx, cfg.Forward); err != nil {
		return err
	}
	if err := m.validateReverse(ctx, cfg.Reverse); err != nil {
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.mu.Unlock()
	if m.Supervise {
		m.ensureProcesses(ctx, cfg)
	}
	return nil
}

func (m *ProxyManager) renderForward(cfg config.ForwardProxyConfig) error {
	path := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	if !cfg.Enabled {
		_ = os.Remove(path)
		return nil
	}
	port := cfg.ListenPort
	if port == 0 {
		port = 3128
	}
	domains := cfg.AllowedDomains
	if len(domains) == 0 {
		domains = []string{"*"}
	}
	domainsJSON, err := json.Marshal(domains)
	if err != nil {
		return err
	}

	tpl := template.Must(template.New("envoyForward").Parse(envoyForwardTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, map[string]any{
		"ListenPort":     port,
		"Domains":        string(domainsJSON),
		"LogRequests":    cfg.LogRequests,
		"Upstream":       cfg.Upstream,
		"HasUpstream":    cfg.Upstream != "",
		"ListenZones":    cfg.ListenZones,
		"HasListenZones": len(cfg.ListenZones) > 0,
	}); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func (m *ProxyManager) renderReverse(cfg config.ReverseProxyConfig) error {
	path := filepath.Join(m.BaseDir, "nginx-reverse.conf")
	if !cfg.Enabled || len(cfg.Sites) == 0 {
		_ = os.Remove(path)
		return nil
	}
	tpl := template.Must(template.New("nginxReverse").Funcs(template.FuncMap{
		"join": func(ss []string, sep string) string {
			if len(ss) == 0 {
				return ""
			}
			out := ss[0]
			for _, s := range ss[1:] {
				out += sep + s
			}
			return out
		},
		"hasCert": func(ref string) bool { return ref != "" },
	}).Parse(nginxReverseTemplate))

	type tmplData struct {
		config.ReverseProxyConfig
		CertsDir string
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData{ReverseProxyConfig: cfg, CertsDir: m.CertsDir}); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func (m *ProxyManager) validateForward(ctx context.Context, cfg config.ForwardProxyConfig) error {
	if !cfg.Enabled {
		return nil
	}
	configPath := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("envoy config missing: %w", err)
	}
	if _, err := os.Stat(m.EnvoyPath); err != nil {
		// Do not fail hard when binary is missing; supervision will log a clearer error.
		return nil
	}
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	testCmd := exec.CommandContext(testCtx, m.EnvoyPath, "--mode", "validate", "-c", configPath)
	if out, err := testCmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			err = fmt.Errorf("%v: %s", err, msg)
		}
		m.mu.Lock()
		m.lastEnvoyError = err.Error()
		m.mu.Unlock()
		m.emit("service.envoy.validate_failed", map[string]any{"error": err.Error()})
		return err
	}
	return nil
}

func (m *ProxyManager) validateReverse(ctx context.Context, cfg config.ReverseProxyConfig) error {
	if !cfg.Enabled || len(cfg.Sites) == 0 {
		return nil
	}
	configPath := filepath.Join(m.BaseDir, "nginx-reverse.conf")
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("nginx config missing: %w", err)
	}
	if _, err := os.Stat(m.NginxPath); err != nil {
		return nil
	}
	testCmd := exec.CommandContext(ctx, m.NginxPath, "-t", "-c", configPath)
	if out, err := testCmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			err = fmt.Errorf("%v: %s", err, msg)
		}
		m.mu.Lock()
		m.lastNginxError = err.Error()
		m.mu.Unlock()
		m.emit("service.nginx.validate_failed", map[string]any{"error": err.Error()})
		return err
	}
	return nil
}

func (m *ProxyManager) ensureProcesses(ctx context.Context, cfg config.ProxyConfig) {
	if cfg.Forward.Enabled {
		m.startOrRestartEnvoy(ctx)
	} else {
		m.stopEnvoy()
	}
	if cfg.Reverse.Enabled {
		m.startOrRestartNginx(ctx)
	} else {
		m.stopNginx()
	}
}

func (m *ProxyManager) startOrRestartEnvoy(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.EnvoyPath); err != nil {
		m.lastEnvoyError = fmt.Sprintf("envoy binary not found at %s", m.EnvoyPath)
		m.logger.Printf("%s; supervision skipped", m.lastEnvoyError)
		return
	}
	configPath := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	if info, err := os.Stat(configPath); err != nil || info.Size() == 0 {
		m.lastEnvoyError = fmt.Sprintf("envoy config missing or empty at %s", configPath)
		m.logger.Printf("%s; skipping start", m.lastEnvoyError)
		return
	}
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		_ = m.envoyCmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
	}
	cmd := exec.CommandContext(ctx, m.EnvoyPath, "-c", configPath, "--log-level", "info")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastEnvoyError = err.Error()
		m.logger.Printf("failed to start envoy: %v", err)
		m.emit("service.envoy.start_failed", map[string]any{"error": err.Error()})
		return
	}
	m.envoyCmd = cmd
	m.lastEnvoyError = ""
	m.lastEnvoyStart = time.Now().UTC()
	m.emit("service.envoy.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath})
	go func() { _ = cmd.Wait() }()
}

func (m *ProxyManager) stopEnvoy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		_ = m.envoyCmd.Process.Signal(os.Interrupt)
		m.emit("service.envoy.stopped", map[string]any{"pid": m.envoyCmd.Process.Pid})
	}
	m.envoyCmd = nil
}

func (m *ProxyManager) startOrRestartNginx(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.NginxPath); err != nil {
		m.lastNginxError = fmt.Sprintf("nginx binary not found at %s", m.NginxPath)
		m.logger.Printf("%s; supervision skipped", m.lastNginxError)
		return
	}
	configPath := filepath.Join(m.BaseDir, "nginx-reverse.conf")
	if info, err := os.Stat(configPath); err != nil || info.Size() == 0 {
		m.lastNginxError = fmt.Sprintf("nginx config missing or empty at %s", configPath)
		m.logger.Printf("%s; skipping start", m.lastNginxError)
		return
	}
	// Validate config before restart.
	if err := m.validateReverse(ctx, m.lastCfg.Reverse); err != nil {
		return
	}
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		_ = m.nginxCmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
	}
	cmd := exec.CommandContext(ctx, m.NginxPath, "-c", configPath, "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastNginxError = err.Error()
		m.logger.Printf("failed to start nginx: %v", err)
		m.emit("service.nginx.start_failed", map[string]any{"error": err.Error()})
		return
	}
	m.nginxCmd = cmd
	m.lastNginxError = ""
	m.lastNginxStart = time.Now().UTC()
	m.emit("service.nginx.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath})
	go func() { _ = cmd.Wait() }()
}

func (m *ProxyManager) stopNginx() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		_ = m.nginxCmd.Process.Signal(os.Interrupt)
		m.emit("service.nginx.stopped", map[string]any{"pid": m.nginxCmd.Process.Pid})
	}
	m.nginxCmd = nil
}

func (m *ProxyManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	envoyRunning := m.envoyCmd != nil && m.envoyCmd.Process != nil
	nginxRunning := m.nginxCmd != nil && m.nginxCmd.Process != nil
	envoyPID := 0
	nginxPID := 0
	if envoyRunning {
		envoyPID = m.envoyCmd.Process.Pid
	}
	if nginxRunning {
		nginxPID = m.nginxCmd.Process.Pid
	}
	return map[string]any{
		"forward_enabled":  m.lastCfg.Forward.Enabled,
		"reverse_enabled":  m.lastCfg.Reverse.Enabled,
		"envoy_path":       m.EnvoyPath,
		"nginx_path":       m.NginxPath,
		"envoy_running":    envoyRunning,
		"nginx_running":    nginxRunning,
		"envoy_pid":        envoyPID,
		"nginx_pid":        nginxPID,
		"envoy_last_start": m.lastEnvoyStart,
		"nginx_last_start": m.lastNginxStart,
		"envoy_last_error": m.lastEnvoyError,
		"nginx_last_error": m.lastNginxError,
		"last_render":      m.lastRender,
		"rendered_files":   m.DescribeRendered(),
	}
}

func (m *ProxyManager) emit(kind string, attrs map[string]any) {
	if m.OnEvent != nil {
		m.OnEvent(kind, attrs)
	}
}

// DescribeRendered returns a human-readable list of rendered files for debugging.
func (m *ProxyManager) DescribeRendered() []string {
	return []string{
		fmt.Sprintf("%s/envoy-forward.yaml", m.BaseDir),
		fmt.Sprintf("%s/nginx-reverse.conf", m.BaseDir),
	}
}

const envoyForwardTemplate = `
static_resources:
  listeners:
  - name: forward_proxy
    address:
      socket_address:
        address: 0.0.0.0
        port_value: {{.ListenPort}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: forward_proxy
          {{- if .LogRequests }}
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
          {{- end }}
          route_config:
            name: local_route
            virtual_hosts:
            - name: forward_proxy
              domains: {{.Domains}}
              routes:
              - match: { prefix: "/" }
                route:
                  cluster: dynamic_forward_proxy_cluster
          {{- if .HasUpstream }}
          # upstream proxy chaining is not yet implemented; Upstream={{.Upstream}}
          {{- end }}
          {{- if .HasListenZones }}
          # listenZones are recorded in config but not yet enforced at L3 binding; listenZones={{.ListenZones}}
          {{- end }}
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache
          - name: envoy.filters.http.router
  clusters:
  - name: dynamic_forward_proxy_cluster
    connect_timeout: 5s
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: dynamic_forward_proxy_cache
          dns_lookup_family: V4_ONLY
admin:
  access_log_path: /tmp/admin_access.log
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901
`

const nginxReverseTemplate = `
{{- range .Sites }}
{{- $site := . }}
upstream {{$site.Name}}_upstream {
{{- range $site.Backends }}
  server {{ . }};
{{- end }}
}

server {
  {{- if $site.TLSEnabled }}
    {{- if hasCert $site.CertRef }}
  listen {{ $site.ListenPort }} ssl;
  ssl_certificate {{ $.CertsDir }}/{{ $site.CertRef }}.crt;
  ssl_certificate_key {{ $.CertsDir }}/{{ $site.CertRef }}.key;
    {{- else }}
  # TLS enabled but certRef not set; serving plaintext until certificates are configured.
  listen {{ $site.ListenPort }};
    {{- end }}
  {{- else }}
  listen {{ $site.ListenPort }};
  {{- end }}
  {{- if $site.Hostnames }}
  server_name {{ join $site.Hostnames " " }};
  {{- else }}
  server_name _;
  {{- end }}

  location / {
    proxy_pass http://{{$site.Name}}_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
{{ end -}}
`
