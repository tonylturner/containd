// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// defaultServicesDir must be writable in the single-container appliance image.
// In docker-compose we mount a persistent volume at /data.
const defaultServicesDir = "/data/services"

const defaultCertsDir = "/data/certs"
const envoyAccessLogPath = "/data/logs/envoy-access.log"
const nginxAccessLogPath = "/data/logs/nginx-access.log"

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
	lastEnvoyStop  time.Time
	lastNginxStop  time.Time
	lastEnvoyExit  string
	lastNginxExit  string
	lastRender     time.Time
	log            *zap.SugaredLogger

	// Optional traffic emitters (e.g., access log tailers) can call these helpers.
	envoyAccessCancel context.CancelFunc
	envoyAccessPath   string
	nginxAccessCancel context.CancelFunc
	nginxAccessPath   string
}

// RecordForwardRequests increments the proxy traffic counter for Envoy forward proxy.
func (m *ProxyManager) RecordForwardRequests(count int, errs int) {
	if count < 0 {
		count = 0
	}
	if errs < 0 {
		errs = 0
	}
	if count > 0 {
		m.emit("service.envoy.requests", map[string]any{"count": count})
	}
	if errs > 0 {
		m.emit("service.envoy.errors", map[string]any{"error_count": errs})
	}
}

// RecordReverseRequests increments the proxy traffic counter for Nginx reverse proxy.
func (m *ProxyManager) RecordReverseRequests(count int, errs int) {
	if count < 0 {
		count = 0
	}
	if errs < 0 {
		errs = 0
	}
	if count > 0 {
		m.emit("service.nginx.requests", map[string]any{"count": count})
	}
	if errs > 0 {
		m.emit("service.nginx.errors", map[string]any{"error_count": errs})
	}
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
	lg, err := commonlog.NewZap("proxy", "proxy", commonlog.Options{
		FilePath: "/data/logs/proxy.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		lg = zap.NewNop().Sugar()
	}
	return &ProxyManager{
		BaseDir:   baseDir,
		Supervise: opts.Supervise,
		EnvoyPath: envoyPath,
		NginxPath: nginxPath,
		CertsDir:  certsDir,
		log:       lg,
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
	logDir := filepath.Join(filepath.Dir(m.BaseDir), "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
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
	m.syncAccessTailers(cfg)
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
		"AccessLogPath":  envoyAccessLogPath,
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
		CertsDir      string
		AccessLogPath string
		PidPath       string
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData{
		ReverseProxyConfig: cfg,
		CertsDir:           m.CertsDir,
		AccessLogPath:      nginxAccessLogPath,
		PidPath:            filepath.Join(m.BaseDir, "nginx.pid"),
	}); err != nil {
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
			err = fmt.Errorf("%w: %s", err, msg)
		}
		m.mu.Lock()
		m.lastEnvoyError = err.Error()
		m.mu.Unlock()
		m.emit("service.envoy.validate_failed", map[string]any{"error": err.Error(), "error_count": 1})
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
			err = fmt.Errorf("%w: %s", err, msg)
		}
		m.mu.Lock()
		m.lastNginxError = err.Error()
		m.mu.Unlock()
		m.emit("service.nginx.validate_failed", map[string]any{"error": err.Error(), "error_count": 1})
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
		m.log.Warnw("envoy binary not found; supervision skipped", "path", m.EnvoyPath)
		return
	}
	configPath := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	if info, err := os.Stat(configPath); err != nil || info.Size() == 0 {
		m.lastEnvoyError = fmt.Sprintf("envoy config missing or empty at %s", configPath)
		m.log.Warnw("envoy config missing; skipping start", "config", configPath)
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
		m.log.Errorw("failed to start envoy", "error", err)
		m.emit("service.envoy.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
		return
	}
	m.envoyCmd = cmd
	m.lastEnvoyError = ""
	m.lastEnvoyStart = time.Now().UTC()
	m.lastEnvoyExit = ""
	m.emit("service.envoy.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})
	pid := cmd.Process.Pid
	go func(cmd *exec.Cmd, pid int) {
		err := cmd.Wait()
		exit := "exited"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		if m.envoyCmd == cmd {
			m.envoyCmd = nil
			m.lastEnvoyStop = time.Now().UTC()
			m.lastEnvoyExit = exit
		}
		m.mu.Unlock()
		m.emit("service.envoy.exited", map[string]any{"pid": pid, "exit": exit, "error_count": 1})
	}(cmd, pid)
}

func (m *ProxyManager) stopEnvoy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		_ = m.envoyCmd.Process.Signal(os.Interrupt)
		m.emit("service.envoy.stopped", map[string]any{"pid": m.envoyCmd.Process.Pid, "count": 1})
	}
	m.envoyCmd = nil
	m.lastEnvoyStop = time.Now().UTC()
}

func (m *ProxyManager) startOrRestartNginx(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.NginxPath); err != nil {
		m.lastNginxError = fmt.Sprintf("nginx binary not found at %s", m.NginxPath)
		m.log.Warnw("nginx binary missing; supervision skipped", "path", m.NginxPath)
		return
	}
	configPath := filepath.Join(m.BaseDir, "nginx-reverse.conf")
	if info, err := os.Stat(configPath); err != nil || info.Size() == 0 {
		m.lastNginxError = fmt.Sprintf("nginx config missing or empty at %s", configPath)
		m.log.Warnw("nginx config missing; skipping start", "config", configPath)
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
		m.log.Errorw("failed to start nginx", "error", err)
		m.emit("service.nginx.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
		return
	}
	m.nginxCmd = cmd
	m.lastNginxError = ""
	m.lastNginxStart = time.Now().UTC()
	m.lastNginxExit = ""
	m.emit("service.nginx.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})
	pid := cmd.Process.Pid
	go func(cmd *exec.Cmd, pid int) {
		err := cmd.Wait()
		exit := "exited"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		if m.nginxCmd == cmd {
			m.nginxCmd = nil
			m.lastNginxStop = time.Now().UTC()
			m.lastNginxExit = exit
		}
		m.mu.Unlock()
		m.emit("service.nginx.exited", map[string]any{"pid": pid, "exit": exit, "error_count": 1})
	}(cmd, pid)
}

func (m *ProxyManager) stopNginx() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		_ = m.nginxCmd.Process.Signal(os.Interrupt)
		m.emit("service.nginx.stopped", map[string]any{"pid": m.nginxCmd.Process.Pid, "count": 1})
	}
	m.nginxCmd = nil
	m.lastNginxStop = time.Now().UTC()
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
		"envoy_last_stop":  m.lastEnvoyStop,
		"nginx_last_stop":  m.lastNginxStop,
		"envoy_last_exit":  m.lastEnvoyExit,
		"nginx_last_exit":  m.lastNginxExit,
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

func (m *ProxyManager) syncAccessTailers(cfg config.ProxyConfig) {
	if !m.Supervise {
		m.stopEnvoyAccessTailer()
		m.stopNginxAccessTailer()
		return
	}
	if cfg.Forward.Enabled && cfg.Forward.LogRequests {
		m.startEnvoyAccessTailer(envoyAccessLogPath)
	} else {
		m.stopEnvoyAccessTailer()
	}
	if cfg.Reverse.Enabled && len(cfg.Reverse.Sites) > 0 {
		m.startNginxAccessTailer(nginxAccessLogPath)
	} else {
		m.stopNginxAccessTailer()
	}
}

func (m *ProxyManager) startEnvoyAccessTailer(path string) {
	m.mu.Lock()
	if m.envoyAccessCancel != nil && m.envoyAccessPath == path {
		m.mu.Unlock()
		return
	}
	if m.envoyAccessCancel != nil {
		m.envoyAccessCancel()
		m.envoyAccessCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.envoyAccessCancel = cancel
	m.envoyAccessPath = path
	m.mu.Unlock()

	go m.tailAccessLog(ctx, "envoy", path, m.RecordForwardRequests)
}

func (m *ProxyManager) stopEnvoyAccessTailer() {
	m.mu.Lock()
	if m.envoyAccessCancel != nil {
		m.envoyAccessCancel()
		m.envoyAccessCancel = nil
		m.envoyAccessPath = ""
	}
	m.mu.Unlock()
}

func (m *ProxyManager) startNginxAccessTailer(path string) {
	m.mu.Lock()
	if m.nginxAccessCancel != nil && m.nginxAccessPath == path {
		m.mu.Unlock()
		return
	}
	if m.nginxAccessCancel != nil {
		m.nginxAccessCancel()
		m.nginxAccessCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.nginxAccessCancel = cancel
	m.nginxAccessPath = path
	m.mu.Unlock()

	go m.tailAccessLog(ctx, "nginx", path, m.RecordReverseRequests)
}

func (m *ProxyManager) stopNginxAccessTailer() {
	m.mu.Lock()
	if m.nginxAccessCancel != nil {
		m.nginxAccessCancel()
		m.nginxAccessCancel = nil
		m.nginxAccessPath = ""
	}
	m.mu.Unlock()
}

func (m *ProxyManager) tailAccessLog(ctx context.Context, service string, path string, record func(count int, errs int)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			m.emit("service."+service+".access_log_open_failed", map[string]any{"error": err.Error(), "error_count": 1})
			time.Sleep(1 * time.Second)
			continue
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			m.emit("service."+service+".access_log_seek_failed", map[string]any{"error": err.Error(), "error_count": 1})
			time.Sleep(1 * time.Second)
			continue
		}

		reader := bufio.NewReader(f)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					select {
					case <-ctx.Done():
						_ = f.Close()
						return
					case <-time.After(250 * time.Millisecond):
						continue
					}
				}
				m.emit("service."+service+".access_log_read_failed", map[string]any{"error": err.Error(), "error_count": 1})
				break
			}
			status := parseAccessStatus(line)
			errs := 0
			if status >= 400 {
				errs = 1
			}
			record(1, errs)
		}
		_ = f.Close()
		time.Sleep(250 * time.Millisecond)
	}
}

func parseAccessStatus(line string) int {
	idx := strings.Index(line, "status=")
	if idx < 0 {
		return 0
	}
	raw := strings.TrimSpace(line[idx+len("status="):])
	end := 0
	for end < len(raw) {
		if raw[end] < '0' || raw[end] > '9' {
			break
		}
		end++
	}
	if end == 0 {
		return 0
	}
	val, err := strconv.Atoi(raw[:end])
	if err != nil {
		return 0
	}
	return val
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
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: {{.AccessLogPath}}
              log_format:
                text_format_source:
                  inline_string: "status=%RESPONSE_CODE%\n"
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
pid {{ .PidPath }};
events {}

http {
  log_format containd_status "status=$status";
  access_log {{ .AccessLogPath }} containd_status;
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
}
`
