// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// newInjector opens the reset injector. Tests replace it.
var newInjector = session.NewInjector

// initIEC builds the IEC104 session table of one engine configuration. An
// inline (NFQUEUE) engine opens the reset injector; when it cannot, the
// configuration is kept, enforce envelopes fail closed and health reports
// it.
func (e *Engine) initIEC(cfg Config, capManager *capture.Manager) {
	store := e.eventStore
	var t *iecTable
	emit := func(evs []iecTelemetry) {
		for _, event := range evs {
			e.recordLearnOutcome([]dpi.Event{{Proto: event.Proto, Kind: event.Kind, Attributes: event.Attributes, Timestamp: event.Timestamp}})
		}
		for _, ev := range t.withSessionTags(evs) {
			store.Append(ev)
		}
	}
	health := newIECHealth(func(outcome, errText string) {
		store.Append(healthEvent(outcome, errText, time.Now()))
	})
	t = newIECTable(cfg.DPIMode, &e.zones)
	t.inventory = e.inventory
	t.learnDelivery = func(id string) {
		e.recordLearnOutcome([]dpi.Event{{Proto: "iec104", Kind: "evidence.delivery", Attributes: map[string]any{"apdu_id": id, "delivery": "delivered"}, Timestamp: time.Now().UTC()}})
	}
	t.dpi = e.dpiMgr
	t.health = health
	t.jobs = e.hooks.blocks
	t.emit = emit
	t.shadow = e.countShadow
	t.markAbort = store.MarkAborted
	t.onError = cfg.OnError
	t.settler = capManager.Settler
	switch {
	case cfg.ResetInjector != nil:
		t.injector = cfg.ResetInjector
	case cfg.NFQueueGroup == 0:
		health.fault(faultInjector, "capture is not inline (NFQUEUE): IEC104 enforcement needs inline verdicts")
	default:
		inj, err := newInjector()
		if err != nil {
			health.fault(faultInjector, "reset injector unavailable: "+err.Error())
		}
		t.injector = inj
	}
	e.iec = t
	e.hooks.iec = t
}

// IEC104Enforcement reports IEC104 enforcement health.
func (e *Engine) IEC104Enforcement() IEC104Enforcement {
	if e == nil || e.iec == nil {
		return IEC104Enforcement{Healthy: true}
	}
	return e.iec.health.status()
}
