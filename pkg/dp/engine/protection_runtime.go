// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (e *Engine) bindProtection(newConfiguration bool) {
	p, epoch, group := e.protection, e.epoch.Load(), e.nfqueueGroup
	p.update(func() {
		p.epoch = epoch
		p.enabled = e.compiler != nil
		p.configured = true
		p.iecFault = ""
		p.steeringFault = false
		if newConfiguration {
			if e.nflogGroup == 0 {
				p.setLocked("nflog", "off", "", 0, 0)
			} else {
				p.setLocked("nflog", "pending", "awaiting NFLOG bind", 0, 0)
			}
		}
		for name := range p.components {
			if strings.HasPrefix(name, "nfqueue:") {
				delete(p.components, name)
			}
		}
		if group != 0 {
			name := fmt.Sprintf("nfqueue:%d", group)
			p.setLocked(name, "pending", "awaiting queue bind", 0, 0)
			c := p.components[name]
			c.Required = p.queue == name
			p.components[name] = c
		}
	})
	e.hooks.active = func() bool { return p.current(epoch) }
	e.hooks.source = func(ev capture.SourceEvent) { p.source(epoch, group, ev) }
	health := e.iec.health
	notify := func() {
		health.mu.Lock()
		defer health.mu.Unlock()
		reasons := []string{}
		policyFault := false
		for cause, reason := range health.faults {
			if cause == faultQueue || cause == faultSteering {
				continue
			}
			if health.active || cause == faultAdmission || cause == faultGateZones || cause == faultAddresses || cause == faultReset && health.ics {
				reasons = append(reasons, reason)
				if cause == faultAdmission || cause == faultGateZones || cause == faultAddresses {
					policyFault = true
				}
			}
		}
		slices.Sort(reasons)
		p.update(func() {
			if p.epoch == epoch {
				p.iecFault = strings.Join(reasons, "; ")
				p.policyFault = policyFault
			}
		})
	}
	health.observe(notify)
	e.gate.mu.Lock()
	e.gate.observe = func(state, reason string) {
		p.update(func() {
			if p.epoch == epoch {
				p.steeringFault = state == "failed"
				p.setLocked("iec-envelope", state, reason, 0, 0)
			}
		})
	}
	e.gate.mu.Unlock()
	notify()
}

func (e *Engine) protectionInstalled(err error, installed bool) {
	p := e.protection
	p.update(func() {
		p.applying = false
		p.installFailed = err != nil
		reason := ""
		if err != nil {
			reason = err.Error()
			if !installed || e.compiler == nil {
				p.setLocked("nft", "failed", reason, 0, 0)
				return
			}
		}
		state := "ready"
		if e.compiler != nil {
			p.status.InstalledApplyID = p.status.ApplyID
		} else {
			p.status.InstalledApplyID = ""
			state = "off"
		}
		p.setLocked("nft", state, reason, 0, 0)
		for name, c := range p.components {
			c.Required = name == "nft" && e.compiler != nil
			p.components[name] = c
		}
		p.envelope, p.direct, p.queue = false, false, ""
		snap := e.ruleSnap.Load()
		if e.compiler != nil && snap != nil {
			if e.compiler.QueueID > 0 {
				for _, entry := range snap.Firewall {
					if !entry.Action.Decides() || entry.ICS.Protocol == "" {
						continue
					}
					if !strings.EqualFold(strings.TrimSpace(entry.ICS.Protocol), "iec104") {
						p.direct = true
						continue
					}
					// Ask the compiler about this transport scope in enforcing mode;
					// monitor entries use the same port envelope but a direct queue.
					scope := entry
					scope.ICS.Mode = "enforce"
					if e.compiler.SteersIEC104(&rules.Snapshot{DPIMode: "enforce", Firewall: []rules.Entry{scope}}) {
						if rules.MonitorICS(entry, snap.DPIMode) {
							p.direct = true
						} else {
							p.envelope = true
						}
					}
				}
			}
			if p.envelope || p.direct {
				p.queue = fmt.Sprintf("nfqueue:%d", e.compiler.QueueID)
				if _, ok := p.components[p.queue]; !ok {
					p.setLocked(p.queue, "pending", p.queue+": awaiting queue bind", 0, 0)
				}
				c := p.components[p.queue]
				c.Required = true
				p.components[p.queue] = c
			}
			for name, required := range map[string]bool{"iec-envelope": p.envelope, "scan-gate": snap.Gate.Enabled, "scanner": snap.Gate.Enabled} {
				c, ok := p.components[name]
				if !ok {
					p.setLocked(name, "pending", "awaiting readiness", 0, 0)
					c = p.components[name]
				}
				c.Required = required
				p.components[name] = c
			}
		}
		currentQueue := fmt.Sprintf("nfqueue:%d", e.nfqueueGroup)
		for name := range p.components {
			if strings.HasPrefix(name, "nfqueue:") && name != p.queue && name != currentQueue {
				delete(p.components, name)
			}
		}
	})
}

// retireCaptureLocked closes the old consumer, delivers its down event and
// reset work, then cancels and joins every run worker before returning.
func (e *Engine) retireCaptureLocked() {
	if e.runCapture != nil {
		e.runCapture.Stop()
	}
	if e.iec != nil && e.iec.jobs != nil && e.runDone != nil {
		e.iec.jobs.flush(e.runDone)
	}
	if e.runCancel != nil {
		e.runCancel()
	}
	if e.runDone != nil {
		<-e.runDone
	}
	e.runCancel, e.runCapture, e.runDone = nil, nil, nil
	e.started.Store(false)
}

// RetryProtection retires only dead capture, leaving policy and healthy NFLOG
// intact. Steering is explicitly reconciled even if ownership did not change.
// The coordinator serializes this call with configuration and installation.
func (e *Engine) RetryProtection(ctx context.Context) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	st := e.Protection()
	e.protection.mu.Lock()
	reconcileSteering := e.protection.steeringFault
	e.protection.mu.Unlock()
	dead := false
	for _, c := range st.Components {
		if e.nfqueueGroup != 0 && c.State == "failed" && c.Name == fmt.Sprintf("nfqueue:%d", e.nfqueueGroup) {
			dead = true
		}
	}
	if dead {
		e.retireCaptureLocked()
		e.policyMu.Lock()
		defer e.policyMu.Unlock()
		e.epoch.Add(1)
		if err := e.newRun(); err != nil {
			return err
		}
		e.bindGate()
		e.bindProtection(false)
	}
	if reconcileSteering {
		e.gate.reconcile()
	}
	e.retryNFLogLocked(ctx, st.State == "degraded")
	return nil
}

// Close joins consumers and workers before application shutdown completes.
func (e *Engine) Close() {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.retireCaptureLocked()
	e.stopNFLogLocked()
	if e.iec != nil {
		e.iec.stopInventory()
		if e.iec.injector != nil {
			_ = e.iec.injector.Close()
		}
	}
}

// ApplyRulesAndReconcile keeps the observation pending through application-owned
// service reconciliation. The callback runs outside lifecycleMu because gate
// reconciliation can switch admission through the engine again. The application
// coordinator serializes this whole operation with other runtime applies.
func (e *Engine) ApplyRulesAndReconcile(ctx context.Context, snap rules.Snapshot, reconcile func()) error {
	p := e.protection
	p.update(func() { p.ruleReconciling = true })
	defer p.update(func() { p.ruleReconciling = false })
	if err := e.ApplyRules(ctx, snap); err != nil {
		return err
	}
	reconcile()
	return nil
}

func (p *protectionState) released() {
	p.update(func() {
		p.status.InstalledApplyID = ""
		p.enabled = false
		p.envelope, p.direct, p.queue = false, false, ""
		p.setLocked("nft", "off", "", 0, 0)
		for name, c := range p.components {
			c.Required = false
			p.components[name] = c
		}
	})
}
