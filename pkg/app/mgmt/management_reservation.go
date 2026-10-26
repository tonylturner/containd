// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

func managementGuardHealth(base string) httpapi.ManagementGuardHealth {
	client := &http.Client{Timeout: time.Second}
	return func(ctx context.Context) (netcfg.ManagementHealth, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/health", nil)
		if err != nil {
			return netcfg.ManagementHealth{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return netcfg.ManagementHealth{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return netcfg.ManagementHealth{}, fmt.Errorf("engine health status %d", resp.StatusCode)
		}
		var body struct {
			ManagementReservation *netcfg.ManagementHealth `json:"managementReservation"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return netcfg.ManagementHealth{}, err
		}
		if body.ManagementReservation == nil {
			return netcfg.ManagementHealth{}, fmt.Errorf("engine health missing managementReservation")
		}
		return *body.ManagementReservation, nil
	}
}
