// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kballard/go-shellquote"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func cliExecuteHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Line string `json:"line"`
	}
	type resp struct {
		Output string `json:"output"`
		Error  string `json:"error,omitempty"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		// Treat blank input as a no-op; the UI console may send empty lines.
		if strings.TrimSpace(r.Line) == "" {
			c.JSON(http.StatusOK, resp{Output: ""})
			return
		}
		apiClient, err := cliAPIForRequest(c, store)
		if err != nil {
			c.JSON(http.StatusOK, resp{Error: err.Error()})
			return
		}
		ctx := cli.WithRole(c.Request.Context(), c.GetString(ctxRoleKey))
		reg := cli.NewRegistry(store, apiClient)
		var buf bytes.Buffer
		if err := reg.ParseAndExecute(ctx, r.Line, &buf); err != nil {
			c.JSON(http.StatusOK, resp{Output: buf.String(), Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp{Output: buf.String()})
	}
}

func cliCommandsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Enumeration needs the API command set, but makes no API requests.
		reg := cli.NewRegistry(store, &cli.API{})
		role := cli.RoleView
		if strings.EqualFold(c.GetString(ctxRoleKey), string(cli.RoleAdmin)) {
			role = cli.RoleAdmin
		}
		c.JSON(http.StatusOK, reg.CommandsForRole(role))
	}
}

func cliCompleteHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		line := c.Query("line")
		if strings.TrimSpace(line) == "" {
			c.JSON(http.StatusOK, []string{})
			return
		}
		tokens, err := shellquote.Split(line)
		if err != nil {
			c.JSON(http.StatusOK, []string{})
			return
		}
		if strings.HasSuffix(line, " ") {
			tokens = append(tokens, "")
		}
		// Enumeration needs the API command set, but makes no API requests.
		reg := cli.NewRegistry(store, &cli.API{})
		role := cli.RoleView
		if strings.EqualFold(c.GetString(ctxRoleKey), string(cli.RoleAdmin)) {
			role = cli.RoleAdmin
		}
		cmds := reg.CommandsForRole(role)
		cmdName, args := matchCommandTokens(tokens, cmds)
		if cmdName == "" {
			c.JSON(http.StatusOK, []string{})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusOK, []string{})
			return
		}
		suggestions := completeCLIArgs(cmdName, args, cfg, cmds)
		c.JSON(http.StatusOK, suggestions)
	}
}

func cliWSHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Line string `json:"line"`
	}
	type resp struct {
		Output string `json:"output"`
		Error  string `json:"error,omitempty"`
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				return false
			}
			u, err := url.Parse(origin)
			if err != nil || u.Host == "" {
				return false
			}
			return strings.EqualFold(u.Host, r.Host)
		},
	}
	return func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		token := strings.TrimSpace(bearerOrCookie(c))
		_ = conn.WriteJSON(resp{Output: "containd in-app CLI. Type 'show version'."})
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			line := strings.TrimSpace(string(msg))
			if strings.HasPrefix(line, "{") {
				var r req
				if err := json.Unmarshal(msg, &r); err == nil && strings.TrimSpace(r.Line) != "" {
					line = r.Line
				}
			}
			if strings.TrimSpace(line) == "" {
				_ = conn.WriteJSON(resp{Output: ""})
				continue
			}
			// Re-read configuration and certificate for every command, including
			// commands on an already established WebSocket after rotation.
			apiClient, err := cliAPIForRequest(c, store)
			if err != nil {
				_ = conn.WriteJSON(resp{Error: err.Error()})
				continue
			}
			// Preserve tokens refreshed by API responses across commands.
			apiClient.Token = token
			ctx := cli.WithRole(c.Request.Context(), c.GetString(ctxRoleKey))
			reg := cli.NewRegistry(store, apiClient)
			var buf bytes.Buffer
			err = reg.ParseAndExecute(ctx, line, &buf)
			token = apiClient.Token
			if err != nil {
				_ = conn.WriteJSON(resp{Output: buf.String(), Error: err.Error()})
				continue
			}
			_ = conn.WriteJSON(resp{Output: buf.String()})
		}
	}
}

func cliAPIForRequest(c *gin.Context, store config.Store) (*cli.API, error) {
	loopbackHostPort := func(addr string, defaultPort string) string {
		addr = strings.TrimSpace(addr)
		port := defaultPort
		if addr == "" {
			return "127.0.0.1:" + port
		}
		if strings.HasPrefix(addr, ":") {
			if p := strings.TrimSpace(strings.TrimPrefix(addr, ":")); p != "" {
				port = p
			}
			return "127.0.0.1:" + port
		}
		if _, p, err := net.SplitHostPort(addr); err == nil && strings.TrimSpace(p) != "" {
			port = strings.TrimSpace(p)
		}
		return "127.0.0.1:" + port
	}

	// Never derive an authenticated destination from request headers.
	if store == nil {
		return nil, errors.New("console: config store unavailable")
	}
	cfg, err := store.Load(c.Request.Context())
	if err != nil {
		return nil, fmt.Errorf("console: load management config: %w", err)
	}
	if cfg == nil {
		return nil, errors.New("console: management config unavailable")
	}
	enableHTTP := cfg.System.Mgmt.EnableHTTP == nil || *cfg.System.Mgmt.EnableHTTP
	enableHTTPS := cfg.System.Mgmt.EnableHTTPS == nil || *cfg.System.Mgmt.EnableHTTPS
	var baseURL string
	var httpClient cli.HTTPClient
	// Always prefer HTTP for internal calls when enabled.
	if enableHTTP {
		addr := firstNonEmpty(cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.ListenAddr, ":8080")
		baseURL = "http://" + loopbackHostPort(addr, "8080")
	} else if enableHTTPS {
		addr := firstNonEmpty(cfg.System.Mgmt.HTTPSListenAddr, ":8443")
		baseURL = "https://" + loopbackHostPort(addr, "8443")
		certFile, _ := mgmttls.ResolveFiles(cfg)
		httpClient, err = consoleHTTPSClient(certFile)
		if err != nil {
			return nil, fmt.Errorf("console: %w", err)
		}
	} else {
		return nil, errors.New("console: no management HTTP or HTTPS listener enabled")
	}
	apiClient := &cli.API{BaseURL: baseURL}
	if httpClient != nil {
		apiClient.Client = httpClient
	}
	// Pass through the caller's bearer token so in-app console commands
	// can access the same protected endpoints as the UI session.
	if tok := strings.TrimSpace(bearerOrCookie(c)); tok != "" {
		apiClient.Token = tok
	}
	return apiClient, nil
}

// consoleHTTPSClient trusts only the configured leaf, not the host's system CAs.
// Use the certificate's own SAN as the verification name while dialing loopback;
// an operator certificate need not contain 127.0.0.1. Normal TLS verification
// (including validity and server usage) remains enabled, with an exact leaf pin
// as an additional constraint even when the leaf is itself a CA.
func consoleHTTPSClient(certFile string) (*http.Client, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read management TLS certificate %q: %w", certFile, err)
	}
	var leaf *x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("parse management TLS certificate %q: expected PEM certificate", certFile)
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("parse management TLS certificate %q: expected PEM certificate", certFile)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse management TLS certificate %q: %w", certFile, err)
		}
		if leaf == nil {
			leaf = cert
		}
		data = rest
	}
	if leaf == nil {
		return nil, fmt.Errorf("parse management TLS certificate %q: no certificates", certFile)
	}
	var name string
	if len(leaf.DNSNames) > 0 {
		name = leaf.DNSNames[0]
	} else if len(leaf.IPAddresses) > 0 {
		name = leaf.IPAddresses[0].String()
	} else {
		return nil, fmt.Errorf("management TLS certificate %q has no DNS or IP subject alternative name", certFile)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &http.Client{
		Timeout: 10 * time.Second,
		// Do not forward bearer tokens through redirects, even to another port
		// on the same hostname or to an HTTP endpoint.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("console: management API redirect refused")
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots,
				ServerName: name,
				VerifyConnection: func(state tls.ConnectionState) error {
					if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, leaf.Raw) {
						return errors.New("console: management TLS certificate does not match configured leaf")
					}
					return nil
				},
			},
		},
	}, nil
}

func matchCommandTokens(tokens []string, available []string) (string, []string) {
	if len(tokens) == 0 {
		return "", nil
	}
	tokensForMatch := tokens
	if len(tokensForMatch) > 0 && tokensForMatch[len(tokensForMatch)-1] == "" {
		tokensForMatch = tokensForMatch[:len(tokensForMatch)-1]
	}
	availSet := map[string]struct{}{}
	for _, a := range available {
		availSet[a] = struct{}{}
	}
	for i := len(tokensForMatch); i > 0; i-- {
		candidate := strings.ToLower(strings.Join(tokensForMatch[:i], " "))
		if _, ok := availSet[candidate]; ok {
			args := tokensForMatch[i:]
			if len(tokens) > 0 && tokens[len(tokens)-1] == "" {
				args = append(args, "")
			}
			return candidate, args
		}
	}
	return "", nil
}
