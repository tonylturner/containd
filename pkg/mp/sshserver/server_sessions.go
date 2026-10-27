// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/cli"
)

type connectionContextKey struct{}

type resetResult struct {
	Status    string   `json:"status"`
	LoggedOut bool     `json:"loggedOut"`
	Warnings  []string `json:"warnings"`
}

type sshConnection struct {
	id        string
	sessionID string // protected by Server.connMu
	socket    net.Conn
	cancel    context.CancelFunc
	reset     atomic.Bool
	result    atomic.Pointer[resetResult]
}

func (c *sshConnection) close() {
	c.cancel()
	_ = c.socket.Close()
}

func (s *Server) trackConnection(nc net.Conn, cancel context.CancelFunc) *sshConnection {
	conn := &sshConnection{id: rand.Text(), socket: nc, cancel: cancel}
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conns == nil {
		s.conns = make(map[*sshConnection]struct{})
	}
	s.conns[conn] = struct{}{}
	return conn
}

func (s *Server) untrackConnection(conn *sshConnection) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	delete(s.conns, conn)
}

// RevokeConnections closes even shell and unauthenticated connections. Only the
// initiating appliance CLI remains long enough to print its reset response.
func (s *Server) RevokeConnections(initiator string) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for conn := range s.conns {
		if initiator != "" && (conn.sessionID == initiator || conn.id == initiator) {
			conn.reset.Store(true)
		} else {
			conn.close()
		}
	}
}

// closeRevokedSessions closes connections whose management session a password
// or MFA change revoked, or whose account was deleted.
func (s *Server) closeRevokedSessions(sessionIDs []string) {
	revoked := make(map[string]struct{}, len(sessionIDs))
	for _, id := range sessionIDs {
		revoked[id] = struct{}{}
	}
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for conn := range s.conns {
		if _, ok := revoked[conn.sessionID]; ok && conn.sessionID != "" {
			conn.close()
		}
	}
}

func connectionFromContext(ctx context.Context) *sshConnection {
	conn, _ := ctx.Value(connectionContextKey{}).(*sshConnection)
	return conn
}

// The CLI HTTP facade intentionally discards success bodies. Preserve reset
// warnings here for SSH presentation without changing ordinary CLI commands.
type resetAwareClient struct {
	client     cli.HTTPClient
	connection *sshConnection
}

func (c *resetAwareClient) Do(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("X-Containd-SSH-Connection", c.connection.id)
	resp, err := c.client.Do(clone)
	if err != nil || req.Method != http.MethodPost || req.URL.Path != "/api/v1/system/factory-reset" || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	var result resetResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid factory reset response: %w", err)
	}
	if result.Status != "reset" || !result.LoggedOut {
		return nil, fmt.Errorf("factory reset response did not confirm reset and logout")
	}
	c.connection.reset.Store(true)
	c.connection.result.Store(&result)
	return resp, nil
}

func (s *Server) writeResetResult(ctx context.Context, out io.Writer) bool {
	conn := connectionFromContext(ctx)
	if conn == nil {
		return false
	}
	result := conn.result.Swap(nil)
	if result == nil {
		return false
	}
	if len(result.Warnings) == 0 {
		writeTTY(out, "Factory reset complete. You will be logged out.\n")
	} else {
		writeTTY(out, "Factory reset applied with warnings; runtime convergence is incomplete:\n")
		for _, warning := range result.Warnings {
			writeTTY(out, "warning: "+warning+"\n")
		}
		writeTTY(out, "You will be logged out.\n")
	}
	return true
}
