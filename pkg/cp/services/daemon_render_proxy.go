// SPDX-License-Identifier: Apache-2.0
package services

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strconv"
	"text/template" // nosemgrep: go.lang.security.audit.xss.import-text-template.import-text-template -- daemon configuration, not HTML.

	"github.com/tonylturner/containd/pkg/cp/config"
)

func (m *ProxyManager) renderForward(cfg config.ForwardProxyConfig) ([]byte, error) {
	if !cfg.Enabled {
		return nil, nil
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
		return nil, err
	}

	tpl := template.Must(template.New("envoyForward").Parse(envoyForwardTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, map[string]any{
		"ListenPort":    port,
		"Domains":       string(domainsJSON),
		"LogRequests":   cfg.LogRequests,
		"AccessLogPath": strconv.Quote(filepath.Join(filepath.Dir(m.BaseDir), "logs", "envoy-access.log")),
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *ProxyManager) renderReverse(cfg config.ReverseProxyConfig) ([]byte, error) {
	if !cfg.Enabled || len(cfg.Sites) == 0 {
		return nil, nil
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

	type tmplData struct {
		config.ReverseProxyConfig
		CertsDir      string
		AccessLogPath string
		PidPath       string
		TempDir       string
	}

	logDir := filepath.Join(filepath.Dir(m.BaseDir), "logs")
	tempDir := filepath.Join(m.BaseDir, "nginx-tmp")
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData{
		ReverseProxyConfig: cfg,
		CertsDir:           m.CertsDir,
		AccessLogPath:      filepath.Join(logDir, "nginx-access.log"),
		PidPath:            filepath.Join(m.BaseDir, "nginx.pid"),
		TempDir:            tempDir,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache
                dns_lookup_family: V4_ONLY
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
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
  client_body_temp_path {{ .TempDir }}/body;
  proxy_temp_path {{ .TempDir }}/proxy;
  fastcgi_temp_path {{ .TempDir }}/fastcgi;
  uwsgi_temp_path {{ .TempDir }}/uwsgi;
  scgi_temp_path {{ .TempDir }}/scgi;
{{- range .Sites }}
{{- $site := . }}
upstream {{$site.Name}}_upstream {
{{- range $site.Backends }}
  server {{ . }};
{{- end }}
}

server {
  {{- if $site.TLSEnabled }}
  listen {{ $site.ListenPort }} ssl;
  ssl_certificate {{ $.CertsDir }}/{{ $site.CertRef }}.crt;
  ssl_certificate_key {{ $.CertsDir }}/{{ $site.CertRef }}.key;
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
