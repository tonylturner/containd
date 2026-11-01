// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestConfigPushParsingDoesNotReconfigureSessions(t *testing.T) {
	dp := newCountingDP(t)
	// No live capture is needed; retain the handler's asynchronous start path.
	dp.startFn = func(context.Context) error { return nil }
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()}, testProtectionCoordinator(t, dp))
	postConfig(t, h, `{"dpiIcsParsing":{"modbus":"strict"}}`)
	if err := dp.waitStart(t); err != nil {
		t.Fatal(err)
	}
	manager := dp.DPI()
	if dp.ICSParsing("modbus") != ics.Strict || dp.ICSParsing("cip") != ics.Tolerant {
		t.Fatal("initial config was not plumbed")
	}
	dp.startFn = func(context.Context) error { return nil }
	postConfig(t, h, `{"dpiIcsParsing":{"modbus":"tolerant","cip":"strict"}}`)
	if err := dp.waitStart(t); err != nil {
		t.Fatal(err)
	}
	if dp.reconfigs.Load() != 1 || dp.DPI() != manager {
		t.Fatal("parsing-only push rebuilt the engine and retired sessions")
	}
	if dp.ICSParsing("modbus") != ics.Tolerant || dp.ICSParsing("cip") != ics.Strict {
		t.Fatal("new decisions did not receive the parsing change")
	}
}

func TestNewEngineParsingOwnsConfigMap(t *testing.T) {
	modes := map[string]string{"dnp3": "strict"}
	e, err := newEngineFor(zap.NewNop().Sugar(), config.DataPlaneConfig{DPIICSParsing: modes}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	modes["dnp3"] = "tolerant"
	if e.ICSParsing("dnp3") != ics.Strict {
		t.Fatal("engine retained caller's mutable config map")
	}
}
