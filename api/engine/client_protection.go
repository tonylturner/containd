// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

const ApplyIDHeader = "X-Containd-Apply-Id"

type applyIDKey struct{}

// NewApplyContext begins one runtime application, including replays of identical
// configuration. Compensation is a separate application and gets a new ID.
func NewApplyContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, applyIDKey{}, rand.Text())
}

func ApplyID(ctx context.Context) string {
	id, _ := ctx.Value(applyIDKey{}).(string)
	return id
}

func UnknownProtection(id string) dpengine.ProtectionStatus {
	return dpengine.ProtectionStatus{ApplyID: id, State: "unknown", ObservedAt: time.Now().UTC(), Components: []dpengine.ProtectionComponent{}, Effects: []dpengine.ProtectionEffect{}}
}

// NormalizeProtection never substitutes a different application's observation.
func NormalizeProtection(st dpengine.ProtectionStatus, expectedID string) dpengine.ProtectionStatus {
	if st.BootID == "" || st.ObservedAt.IsZero() || expectedID != "" && st.ApplyID != expectedID {
		return UnknownProtection(expectedID)
	}
	switch st.State {
	case "pending", "protecting", "degraded", "failed", "disabled", "unknown":
	default:
		return UnknownProtection(expectedID)
	}
	if st.Components == nil {
		st.Components = []dpengine.ProtectionComponent{}
	}
	if st.Effects == nil {
		st.Effects = []dpengine.ProtectionEffect{}
	}
	return st
}

// ProtectionConflict preserves the engine's atomic retry admission decision.
type ProtectionConflict struct{ Code string }

func (e *ProtectionConflict) Error() string { return e.Code }

func (c *HTTPClient) RetryProtection(ctx context.Context, bootID, applyID string) error {
	body, err := json.Marshal(map[string]string{"bootId": bootID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/protection/retry", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ApplyIDHeader, applyID)
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	if resp.StatusCode == http.StatusConflict {
		var failure struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&failure); err != nil {
			return fmt.Errorf("engine protection retry response: %w", err)
		}
		if failure.Code == "protection_superseded" || failure.Code == "protection_not_retryable" {
			return &ProtectionConflict{Code: failure.Code}
		}
		return fmt.Errorf("engine protection retry conflict: %s", failure.Code)
	}
	return engineStatusError(resp, "engine protection retry status")
}
