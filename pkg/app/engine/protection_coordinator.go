// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

// applyReplayWindow exceeds the management client and engine read deadlines.
// IDs remain opaque; only the local monotonic supersession time is compared.
const applyReplayWindow = 5 * time.Minute

type protectionPlane interface {
	SetProtectionBootID(string)
	BeginProtection(bootID, applyID string)
	BindProtection(protection.Metadata)
	SetProtectionOutcome(protection.Metadata, protection.OwnerOutcome)
	Protection() engine.ProtectionStatus
	StartProtection(retryContext, lifetime context.Context) error
	RetryProtection(context.Context) error
	Close()
}

// protectionCoordinator serializes admission and synchronous side effects, not
// asynchronous readiness. A worker can finish without ending an adopted run.
type protectionCoordinator struct {
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	dp            protectionPlane
	logger        *zap.SugaredLogger
	seen          map[string]time.Time // superseded IDs only
	now           func() time.Time
	current       string
	metadata      protection.Metadata
	inputs        map[string]string
	completed     map[string]bool
	workerCancel  context.CancelFunc
	workerDone    chan struct{}
	closed        bool
	retryServices func(context.Context, protection.Metadata) ([]protection.OwnerOutcome, error)
}

func newProtectionCoordinator(ctx context.Context, dp protectionPlane, logger *zap.SugaredLogger) *protectionCoordinator {
	ctx, cancel := context.WithCancel(ctx)
	dp.SetProtectionBootID(engineBootID)
	return &protectionCoordinator{ctx: ctx, cancel: cancel, dp: dp, logger: logger, seen: map[string]time.Time{}, now: time.Now}
}

func protectionError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": message, "code": code})
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
		admission, ok := readAdmission(w, r)
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
		arrived := c.now()
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.Context().Err() != nil || c.now().Sub(arrived) >= applyReplayWindow {
			protectionError(w, http.StatusRequestTimeout, "apply_expired", "application request expired before admission")
			return
		}
		st := c.dp.Protection()
		id := string(admission.ApplyID)
		if c.closed || admission.Metadata != c.metadata || id != c.current || body.BootID != st.BootID {
			protectionError(w, http.StatusConflict, "protection_superseded", "protection observation was superseded")
			return
		}
		serviceRetryable := false
		for _, out := range st.Subsystems {
			serviceRetryable = serviceRetryable || out.Retryable
		}
		if !st.Retryable && !serviceRetryable {
			protectionError(w, http.StatusConflict, "protection_not_retryable", "protection is not retryable")
			return
		}
		c.joinWorker()
		defer c.start()
		retryCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		stop := context.AfterFunc(c.ctx, cancel)
		defer stop()
		defer cancel()
		if c.retryServices != nil {
			outcomes, err := c.retryServices(retryCtx, admission.Metadata)
			for _, out := range outcomes {
				c.dp.SetProtectionOutcome(admission.Metadata, out)
			}
			if err != nil {
				protectionError(w, http.StatusConflict, "service_delivery_changed", "service owner requires a fresh delivery attempt")
				return
			}
		}
		if err := c.dp.RetryProtection(retryCtx); err != nil {
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
