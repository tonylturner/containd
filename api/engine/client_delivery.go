// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

var _ convergence.EngineClient = (*HTTPClient)(nil)

// delivery posts immutable admitted input. Transport success is never owner
// proof; only Observe can return the engine's independently collected ledger.
func (c *HTTPClient) delivery(ctx context.Context, admission protection.Admission, path string, input any) error {
	if c.BaseURL == "" {
		return fmt.Errorf("engine BaseURL is empty")
	}
	if !admission.Valid() {
		return fmt.Errorf("invalid engine admission")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protection.ApplyIDHeader, string(admission.ApplyID))
	req.Header.Set(protection.EngineBootIDHeader, string(admission.BootID))
	req.Header.Set(protection.RunningRevisionHeader, string(admission.RunningRevision))
	req.Header.Set(protection.ApplyModeHeader, string(admission.Mode))
	// Presence matters on a fresh boot, even when the predecessor is empty.
	req.Header.Set(protection.PreviousApplyIDHeader, string(admission.PreviousApplyID))
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusConflict {
		var failure struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&failure); err != nil {
			return fmt.Errorf("engine conflict: %w", err)
		}
		switch failure.Code {
		case "apply_input_changed", "apply_predecessor_changed", "engine_boot_changed", "apply_superseded", "protection_superseded", "apply_target_changed", "service_delivery_changed":
			return fmt.Errorf("%w: %s", convergence.ErrInputChanged, failure.Code)
		default:
			return fmt.Errorf("engine conflict: %s", failure.Code)
		}
	}
	return readStatusError(resp, "delivery")
}

func (c *HTTPClient) Configure(ctx context.Context, a protection.Admission, cfg config.DataPlaneConfig) error {
	return c.delivery(ctx, a, "/internal/config", cfg)
}

func (c *HTTPClient) ConfigureServices(ctx context.Context, a protection.Admission, cfg config.ServicesConfig) error {
	return c.delivery(ctx, a, "/internal/services", cfg)
}

func (c *HTTPClient) ConfigureTrust(ctx context.Context, a protection.Admission, bundle trust.Bundle) error {
	return c.delivery(ctx, a, "/internal/trust", bundle)
}

func (c *HTTPClient) ApplyRules(ctx context.Context, a protection.Admission, snapshot rules.Snapshot) error {
	return c.delivery(ctx, a, "/internal/apply_rules", snapshot)
}

func (c *HTTPClient) ConfigureInterfaces(ctx context.Context, a protection.Admission, cfg []config.Interface, replace bool) error {
	return c.delivery(ctx, a, replacePath("/internal/interfaces", replace), cfg)
}

func (c *HTTPClient) ConfigureRouting(ctx context.Context, a protection.Admission, cfg config.RoutingConfig, replace bool) error {
	return c.delivery(ctx, a, replacePath("/internal/routing", replace), cfg)
}

func replacePath(path string, replace bool) string {
	if replace {
		return path + "?mode=replace"
	}
	return path
}

func (c *HTTPClient) Retry(ctx context.Context, a protection.Admission) error {
	return c.delivery(ctx, a, "/internal/protection/retry", map[string]string{"bootId": string(a.BootID)})
}

func (c *HTTPClient) Observe(ctx context.Context) (convergence.Observation, error) {
	health, err := c.RuntimeHealth(ctx)
	if err != nil {
		return convergence.Observation{}, err
	}
	st := health.Protection
	degraded := st.State == "degraded"
	// Schedule degradation does not revoke packet installation, but gates ready.
	status, err := c.RulesetStatus(ctx)
	if err != nil {
		// The boot remains admissible. Missing ancillary telemetry must not
		// turn a successful synchronous policy install into a rollback error,
		// but it also cannot certify clean protection.
		st.State = string(protection.StateUnknown)
	}
	if status.SchedulePlanner != nil && status.SchedulePlanner.State == dpengine.SchedulePlannerDegraded {
		degraded = true
	}
	return convergence.Observation{
		BootID: protection.BootID(health.BootID), Engine: st.Observation(),
		Outcomes: st.Subsystems, Degraded: degraded, Retryable: st.Retryable,
	}, nil
}
