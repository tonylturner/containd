// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sync"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// newRun creates one consumer and its complete hook/settlement wiring. The
// caller owns lifecycleMu and has already joined any previous run.
func (e *Engine) newRun() error {
	hooks := newInlineHooks(e.onError)
	cfg := e.captureConfig
	onError := cfg.OnError
	cfg.OnError = func(err error) {
		hooks.onCaptureError(err)
		if onError != nil {
			onError(err)
		}
	}
	cfg.OnSource, cfg.OnVerdict = hooks.onSource, hooks.onVerdict
	cfg.PublicationFence = &e.policyMu
	factory := e.captureFactory
	if factory == nil {
		factory = func(cfg capture.Config) (CaptureRunner, error) { return capture.NewManager(cfg) }
	}
	runner, err := factory(cfg)
	if err != nil {
		return err
	}
	if fenced, ok := runner.(interface{ SetPublicationFence(*sync.RWMutex) }); ok {
		fenced.SetPublicationFence(&e.policyMu)
	}
	e.capture, e.hooks = runner, hooks
	hooks.sessions = e.sessions
	e.sessions.settler = runner.Settler
	e.sessions.jobs = hooks.blocks
	return nil
}
