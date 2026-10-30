// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
		apiClient, err := cliAPIForRequest(c)
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
		// The route requires a single-use ticket minted by an authenticated,
		// CSRF-protected POST. That capability, not ambient cookies, authorizes
		// the upgrade. Comparing Origin with Host adds no CSWSH protection and
		// rejects reverse proxies that strip the published port from Host.
		CheckOrigin: func(*http.Request) bool { return true },
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
			apiClient, err := cliAPIForRequest(c)
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

// cliAPIForRequest is the API client of an in-app console command: it calls
// the management API on loopback as SSH CLI sessions do (see
// LoopbackManagementAPI), with the caller's bearer token.
func cliAPIForRequest(c *gin.Context) (*cli.API, error) {
	baseURL, client, err := LoopbackManagementAPI()
	if err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	apiClient := &cli.API{BaseURL: baseURL, Client: client}
	// Pass through the caller's bearer token so in-app console commands
	// can access the same protected endpoints as the UI session.
	if tok := strings.TrimSpace(bearerOrCookie(c)); tok != "" {
		apiClient.Token = tok
	}
	return apiClient, nil
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
