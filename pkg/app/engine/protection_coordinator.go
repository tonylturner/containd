// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

const applyIDHeader = "X-Containd-Apply-Id"

// applyReplayWindow exceeds the management client and engine read deadlines.
// IDs remain opaque; only the local monotonic supersession time is compared.
const applyReplayWindow = 5 * time.Minute

type protectionPlane interface {
	SetProtectionBootID(string)
	BeginProtection(bootID, applyID string)
	Protection() engine.ProtectionStatus
	StartProtection(retryContext, lifetime context.Context) error
	RetryProtection(context.Context) error
	Close()
}

// protectionCoordinator serializes admission and synchronous side effects, not
// asynchronous readiness. A worker can finish without ending an adopted run.
type protectionCoordinator struct {
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	dp           protectionPlane
	logger       *zap.SugaredLogger
	seen         map[string]time.Time // superseded IDs only
	now          func() time.Time
	current      string
	workerCancel context.CancelFunc
	workerDone   chan struct{}
	closed       bool
}

func newProtectionCoordinator(ctx context.Context, dp protectionPlane, logger *zap.SugaredLogger) *protectionCoordinator {
	ctx, cancel := context.WithCancel(ctx)
	dp.SetProtectionBootID(engineBootID)
	return &protectionCoordinator{ctx: ctx, cancel: cancel, dp: dp, logger: logger, seen: map[string]time.Time{}, now: time.Now}
}

func applyID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.Header.Get(applyIDHeader)
	if strings.TrimSpace(id) == "" || len(id) > 64 {
		protectionError(w, http.StatusBadRequest, "invalid_apply_id", "X-Containd-Apply-Id must contain 1 to 64 bytes")
		return "", false
	}
	return id, true
}

func protectionError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": message, "code": code})
}

func (c *protectionCoordinator) admit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next(w, r)
			return
		}
		id, ok := applyID(w, r)
		if !ok {
			return
		}
		arrived := c.now()
		c.mu.Lock()
		defer c.mu.Unlock()
		now := c.now()
		// Client timeouts do not bound time spent waiting for this lock.
		// Never admit a queued request after its replay protection expires.
		if r.Context().Err() != nil || now.Sub(arrived) >= applyReplayWindow {
			protectionError(w, http.StatusRequestTimeout, "apply_expired", "application request expired before admission")
			return
		}
		if c.closed {
			protectionError(w, http.StatusServiceUnavailable, "engine_stopping", "engine stopping")
			return
		}
		for old, superseded := range c.seen {
			if now.Sub(superseded) >= applyReplayWindow {
				delete(c.seen, old)
			}
		}
		if _, superseded := c.seen[id]; superseded {
			protectionError(w, http.StatusConflict, "apply_superseded", "application was superseded")
			return
		}
		// Every mutating phase re-enters pending: a repeated config/services
		// request cannot reuse an earlier rules acknowledgement for this ID.
		c.dp.BeginProtection(engineBootID, id)
		if id != c.current {
			if c.current != "" {
				c.seen[c.current] = now
			}
			c.current = id
		}
		next(w, r)
	}
}

// Caller holds mu. Only the retry loop is canceled here: a healthy run uses
// c.ctx and survives adoption by a subsequent unchanged configuration.
func (c *protectionCoordinator) joinWorker() {
	if c.workerCancel != nil {
		c.workerCancel()
		<-c.workerDone
		c.workerCancel = nil
		c.workerDone = nil
	}
}

func (c *protectionCoordinator) start() {
	c.joinWorker()
	retryCtx, cancel := context.WithCancel(c.ctx)
	done := make(chan struct{})
	c.workerCancel, c.workerDone = cancel, done
	go func() {
		defer close(done)
		if err := c.dp.StartProtection(retryCtx, c.ctx); err != nil && retryCtx.Err() == nil {
			c.logger.Errorf("capture start failed: %v", err)
		}
	}()
}

func (c *protectionCoordinator) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.cancel()
	c.joinWorker()
	c.dp.Close()
}

func (c *protectionCoordinator) retryHandler(gate *gateManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, ok := applyID(w, r)
		if !ok {
			return
		}
		var body struct {
			BootID string `json:"bootId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		st := c.dp.Protection()
		if c.closed || id != c.current || body.BootID != st.BootID {
			protectionError(w, http.StatusConflict, "protection_superseded", "protection observation was superseded")
			return
		}
		if !st.Retryable {
			protectionError(w, http.StatusConflict, "protection_not_retryable", "protection is not retryable")
			return
		}
		c.joinWorker()
		defer c.start()
		if err := c.dp.RetryProtection(c.ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if gate != nil {
			gate.syncAdmit()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, map[string]string{"status": "retrying", "applyId": id})
	}
}
