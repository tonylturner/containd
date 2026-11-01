// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
	"go.uber.org/zap"
)

type adoptionCapture struct {
	source func(capture.SourceEvent)
	starts atomic.Int32
}

func (c *adoptionCapture) Start(context.Context, capture.Handler) error {
	c.starts.Add(1)
	c.source(capture.SourceEvent{Ready: true})
	return nil
}
func (c *adoptionCapture) Stop() {
	c.source(capture.SourceEvent{Err: capture.ErrQueueClosed})
}
func (*adoptionCapture) Interfaces() []string     { return nil }
func (*adoptionCapture) Settler() capture.Settler { return nil }
func (*adoptionCapture) RetireFlushed()           {}

type adoptionApplier struct{}

func (adoptionApplier) Apply(context.Context, string) error { return nil }
func (adoptionApplier) ReadTable(context.Context, string) (enforce.TableLayout, error) {
	return enforce.TableLayout{}, nil
}

// Replace only OS capture and nft I/O. Configure, unchanged/parsing-only
// detection, engine run ownership, callbacks and rule installation remain real.
type adoptionPlane struct {
	*countingDP
	runner *adoptionCapture
}

func (p *adoptionPlane) Reconfigure(fresh *engine.Engine) error {
	fresh.Close()
	p.reconfigs.Add(1)
	next, err := engine.New(engine.Config{
		Events: p.Events(), NFQueueGroup: 101, DPIEnabled: true, DPIMode: "monitor",
		ResetInjector: &session.Fake{},
		Enforce: engine.EnforceConfig{
			Enabled: true, Applier: adoptionApplier{},
			ClearMark: func(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil },
		},
		NewCapture: func(cfg capture.Config) (engine.CaptureRunner, error) {
			p.runner = &adoptionCapture{source: cfg.OnSource}
			return p.runner, nil
		},
	})
	if err != nil {
		return err
	}
	return p.Engine.Reconfigure(next)
}

func TestProtectionConfigureAdoptsRunAcrossApplyIDsThenObservesLoss(t *testing.T) {
	for _, mode := range []string{"unchanged", "parsing-only"} {
		t.Run(mode, func(t *testing.T) {
			dp := &adoptionPlane{countingDP: newCountingDP(t)}
			c := testProtectionCoordinator(t, dp)
			logger := zap.NewNop().Sugar()
			conf := configHandler(logger, dp, &simulationManager{dpEngine: dp.Engine, logger: logger}, c)
			apply := applyRulesHandler(dp.Engine, nil, c)
			snap, err := json.Marshal(rules.Snapshot{DPIMode: "monitor", Firewall: []rules.Entry{
				{ID: "direct", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			const base = `{"enforcement":true,"nfqueueGroup":101,"dpiEnabled":true,"dpiMode":"monitor"}`
			for _, id := range []string{"A", "B"} {
				body := base
				if mode == "parsing-only" && id == "B" {
					body = `{"enforcement":true,"nfqueueGroup":101,"dpiEnabled":true,"dpiMode":"monitor","dpiIcsParsing":{"modbus":"strict"}}`
				}
				if w := coordinatedPost(conf, id, body); w.Code != 200 {
					t.Fatalf("Configure(%s): %d %s", id, w.Code, w.Body)
				}
				if err := dp.waitStart(t); err != nil {
					t.Fatal(err)
				}
				if w := coordinatedPost(apply, id, string(snap)); w.Code != 200 {
					t.Fatalf("ApplyRules(%s): %d %s", id, w.Code, w.Body)
				}
				if st := dp.Protection(); st.State != "protecting" || st.ApplyID != id || st.InstalledApplyID != id {
					t.Fatalf("adopted apply: %+v", st)
				}
			}
			if dp.reconfigs.Load() != 1 || dp.runner.starts.Load() != 1 {
				t.Fatalf("adoption rebuilt/rebound: configurations=%d starts=%d", dp.reconfigs.Load(), dp.runner.starts.Load())
			}
			dp.runner.source(capture.SourceEvent{Terminal: true, Err: errors.New("adopted consumer lost")})
			if st := dp.Protection(); st.State != "failed" || st.ApplyID != "B" || !st.Retryable {
				t.Fatalf("loss was not attributed to adopted application: %+v", st)
			}
		})
	}
}
