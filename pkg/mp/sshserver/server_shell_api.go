// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cli"
)

const shellResetCloseGrace = 2 * time.Second

// shellAPI lets CLI processes in one Linux shell call management as the SSH
// login that opened the shell. It listens on a Unix socket in a private
// directory and forwards /api/v1 requests with the connection's credentials,
// so the shell receives no token or password.
type shellAPI struct {
	dir    string
	socket string
	server *http.Server
}

func (s *Server) openShellAPI(conn *sshConnection) (*shellAPI, error) {
	dir, err := os.MkdirTemp("", "containd-ssh-")
	if err != nil {
		return nil, err
	}
	socket := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	server := &http.Server{Handler: s.shellAPIHandler(conn), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(ln) }()
	return &shellAPI{dir: dir, socket: socket, server: server}, nil
}

// close stops forwarding and removes the socket.
func (a *shellAPI) close() {
	_ = a.server.Close()
	_ = os.RemoveAll(a.dir)
}

// shellAPIHandler forwards management API requests through the connection's
// client, which authenticates them and names the connection.
func (s *Server) shellAPIHandler(conn *sshConnection) http.Handler {
	client := s.connectionClient(conn)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == cli.SSHResetAcknowledgePath && r.Method == http.MethodPost {
			if !conn.reset.Load() {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			conn.close()
			return
		}
		if !shellAPIPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		target := s.opts.BaseURL + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		if err != nil {
			shellAPIError(w, http.StatusBadRequest, err)
			return
		}
		req.ContentLength = r.ContentLength
		for _, name := range []string{"Content-Type", "Accept"} {
			if v := r.Header.Get(name); v != "" {
				req.Header.Set(name, v)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			shellAPIError(w, http.StatusBadGateway, err)
			return
		}
		defer resp.Body.Close()
		for name, values := range resp.Header {
			// Credentials stay with the SSH server.
			if name == "Set-Cookie" || name == "X-Auth-Token" {
				continue
			}
			w.Header()[name] = values
		}
		if conn.reset.Load() {
			w.Header().Set(cli.SSHResetResponseHeader, "true")
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		if conn.reset.Load() {
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.AfterFunc(shellResetCloseGrace, conn.close)
		}
	})
}

// shellAPIPath reports whether p names a management API path: below
// /api/v1/, without empty, "." or ".." segments.
func shellAPIPath(p string) bool {
	rest, ok := strings.CutPrefix(p, "/api/v1/")
	if !ok || rest == "" {
		return false
	}
	for _, segment := range strings.Split(rest, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func shellAPIError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
