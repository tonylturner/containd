// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// These fixtures exercise revisioned reads and reject missing/stale writes
// before invoking the simulated mutation.
type sshTestRevision struct {
	mu      sync.Mutex
	counter uint64
}

func (s *sshTestRevision) respond(req *http.Request, next func() *http.Response) *http.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counter == 0 {
		s.counter = 1
	}
	revision := fmt.Sprintf("0123456789abcdef.%d", s.counter)
	write := req.Method != http.MethodGet
	if write && req.Header.Get("X-Containd-If-Revision") != revision {
		return jsonResponse(http.StatusPreconditionFailed, map[string]string{
			"code": "config_revision_mismatch", "currentRevision": revision,
		})
	}
	resp := next()
	if resp.StatusCode < http.StatusBadRequest {
		if write {
			s.counter++
			revision = fmt.Sprintf("0123456789abcdef.%d", s.counter)
		}
		resp.Header.Set("X-Containd-Revision", revision)
	}
	return resp
}

func revisionedSSHResetHandler(reset http.HandlerFunc) http.Handler {
	var revision sshTestRevision
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/config/candidate" {
			resp := revision.respond(r, func() *http.Response {
				return jsonResponse(http.StatusOK, config.DefaultConfig())
			})
			defer resp.Body.Close()
			w.Header().Set("X-Containd-Revision", resp.Header.Get("X-Containd-Revision"))
			_ = json.NewEncoder(w).Encode(config.DefaultConfig())
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/system/factory-reset" {
			resp := revision.respond(r, func() *http.Response {
				return jsonResponse(http.StatusOK, nil)
			})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				w.WriteHeader(resp.StatusCode)
				return
			}
			w.Header().Set("X-Containd-Revision", resp.Header.Get("X-Containd-Revision"))
			reset(w, r)
			return
		}
		reset(w, r)
	})
}
