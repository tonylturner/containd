// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"strings"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func startConfigReload(ctx context.Context, logger *zap.SugaredLogger, store config.Store, audits audit.Store, engine httpapi.EngineClient, services httpapi.ServicesApplier, requests <-chan struct{}) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-requests:
				if !ok {
					return
				}
				reloadRunningConfig(ctx, logger, store, audits, engine, services)
			}
		}
	}()
	return func() { cancel(); <-done }
}

func reloadRunningConfig(ctx context.Context, logger *zap.SugaredLogger, store config.Store, audits audit.Store, engine httpapi.EngineClient, services httpapi.ServicesApplier) {
	applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	warnings, err := httpapi.ApplyRunningConfig(applyCtx, store, engine, services)
	record := audit.Record{Actor: "system", Source: "signal", Action: "config.reload", Target: "running", Result: "success"}
	for _, warning := range warnings {
		logger.Warnw("SIGHUP reload warning", "warning", warning)
	}
	record.Detail = strings.Join(warnings, "; ")
	if err != nil {
		record.Result = "failure"
		record.Detail = err.Error()
		logger.Errorw("SIGHUP running configuration reload failed", "error", err)
	} else {
		if len(warnings) > 0 {
			record.Result = "warning"
		}
		logger.Infow("SIGHUP running configuration reapplied; environment and flags require restart", "warnings", warnings)
	}
	audit.Write(ctx, audits, record)
}
