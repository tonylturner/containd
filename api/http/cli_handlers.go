// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kballard/go-shellquote"

	"github.com/tonylturner/containd/pkg/cli"
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
		ctx, reg := cliRegistryForRequest(c, store)
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
		_, reg := cliRegistryForRequest(c, store)
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
		_, reg := cliRegistryForRequest(c, store)
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

		ctx, reg := cliRegistryForRequest(c, store)
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
			var buf bytes.Buffer
			if err := reg.ParseAndExecute(ctx, line, &buf); err != nil {
				_ = conn.WriteJSON(resp{Output: buf.String(), Error: err.Error()})
				continue
			}
			_ = conn.WriteJSON(resp{Output: buf.String()})
		}
	}
}

func cliRegistryForRequest(c *gin.Context, store config.Store) (context.Context, *cli.Registry) {
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

	// Prefer an in-process loopback URL rather than reusing the incoming
	// request Host/scheme. This avoids:
	// - HTTPS self-signed verification errors for internal calls
	// - SSRF-style token exfiltration via crafted Host headers
	baseURL := ""
	var httpClient cli.HTTPClient
	if cfg, err := store.Load(c.Request.Context()); err == nil && cfg != nil {
		enableHTTP := cfg.System.Mgmt.EnableHTTP == nil || *cfg.System.Mgmt.EnableHTTP
		enableHTTPS := cfg.System.Mgmt.EnableHTTPS == nil || *cfg.System.Mgmt.EnableHTTPS

		httpAddr := firstNonEmpty(cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.ListenAddr, ":8080")
		httpsAddr := firstNonEmpty(cfg.System.Mgmt.HTTPSListenAddr, ":8443")

		// Always prefer HTTP for internal calls when enabled.
		if enableHTTP {
			baseURL = "http://" + loopbackHostPort(httpAddr, "8080")
		} else if enableHTTPS {
			baseURL = "https://" + loopbackHostPort(httpsAddr, "8443")
			httpClient = &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						MinVersion:         tls.VersionTLS13,
						InsecureSkipVerify: true, // nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification -- internal CLI calls target the local mgmt listener, which may use a self-signed appliance cert.
					},
				},
			}
		}
	}
	if baseURL == "" {
		// Fallback (should be rare): infer from the request and keep the current Host.
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
			proto = strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
			if proto == "http" || proto == "https" {
				scheme = proto
			}
		}
		baseURL = scheme + "://" + c.Request.Host
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
	ctx := cli.WithRole(c.Request.Context(), c.GetString(ctxRoleKey))
	reg := cli.NewRegistry(store, apiClient)
	return ctx, reg
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
