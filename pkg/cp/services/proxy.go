package services

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"text/template"
	"time"

	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
)

const defaultServicesDir = "/var/lib/containd/services"

type ProxyOptions struct {
	BaseDir   string
	Supervise bool
	EnvoyPath string
	NginxPath string
}

// ProxyManager renders Envoy (forward) and Nginx (reverse) configs from persistent models.
// If Supervise is enabled and binaries exist, it will also start/stop them.
type ProxyManager struct {
	BaseDir   string
	Supervise bool
	EnvoyPath string
	NginxPath string

	mu       sync.Mutex
	lastCfg  config.ProxyConfig
	envoyCmd *exec.Cmd
	nginxCmd *exec.Cmd
	logger   *log.Logger
}

func NewProxyManager(opts ProxyOptions) *ProxyManager {
	baseDir := opts.BaseDir
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
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
		logger:    logging.New("[services/proxy]"),
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
	tpl := template.Must(template.New("envoyForward").Parse(envoyForwardTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, map[string]any{
		"ListenPort": port,
		"Upstream":   cfg.Upstream,
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
	}).Parse(nginxReverseTemplate))

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, cfg); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
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
		m.logger.Printf("envoy binary not found at %s; supervision skipped", m.EnvoyPath)
		return
	}
	configPath := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		_ = m.envoyCmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
	}
	cmd := exec.CommandContext(ctx, m.EnvoyPath, "-c", configPath, "--log-level", "info")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.logger.Printf("failed to start envoy: %v", err)
		return
	}
	m.envoyCmd = cmd
	go func() { _ = cmd.Wait() }()
}

func (m *ProxyManager) stopEnvoy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		_ = m.envoyCmd.Process.Signal(os.Interrupt)
	}
	m.envoyCmd = nil
}

func (m *ProxyManager) startOrRestartNginx(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.NginxPath); err != nil {
		m.logger.Printf("nginx binary not found at %s; supervision skipped", m.NginxPath)
		return
	}
	configPath := filepath.Join(m.BaseDir, "nginx-reverse.conf")
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		_ = m.nginxCmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
	}
	cmd := exec.CommandContext(ctx, m.NginxPath, "-c", configPath, "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.logger.Printf("failed to start nginx: %v", err)
		return
	}
	m.nginxCmd = cmd
	go func() { _ = cmd.Wait() }()
}

func (m *ProxyManager) stopNginx() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		_ = m.nginxCmd.Process.Signal(os.Interrupt)
	}
	m.nginxCmd = nil
}

func (m *ProxyManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"forward_enabled": m.lastCfg.Forward.Enabled,
		"reverse_enabled": m.lastCfg.Reverse.Enabled,
		"envoy_path":      m.EnvoyPath,
		"nginx_path":      m.NginxPath,
		"envoy_running":   m.envoyCmd != nil && m.envoyCmd.Process != nil,
		"nginx_running":   m.nginxCmd != nil && m.nginxCmd.Process != nil,
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
          route_config:
            name: local_route
            virtual_hosts:
            - name: forward_proxy
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route:
                  cluster: dynamic_forward_proxy_cluster
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
  listen {{ $site.ListenPort }};
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
