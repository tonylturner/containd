// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ConfigFailure retains precondition details without retrying an operator's edit.
type ConfigFailure struct {
	Status          int             `json:"-"`
	Code            string          `json:"code"`
	CurrentRevision config.Revision `json:"currentRevision"`
	Message         string          `json:"error"`
}

func (e *ConfigFailure) Error() string {
	return fmt.Sprintf("unexpected status %d (%s): %s; reload and review before retrying", e.Status, e.Code, e.Message)
}

func mutationError(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusPreconditionRequired {
		failure := &ConfigFailure{Status: resp.StatusCode}
		if err := json.Unmarshal(body, failure); err != nil {
			return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
		}
		return failure
	}
	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
}

// Direct-intent commands read the candidate in the same invocation. Commands
// that modify a payload instead pass its read revision explicitly to saveJSON.
func isConfigWrite(path string) bool {
	switch path {
	case "/api/v1/dataplane", "/api/v1/routing", "/api/v1/system/factory-reset",
		"/api/v1/templates/apply", "/api/v1/learn/apply", "/api/v1/services/syslog":
		return true
	}
	for _, prefix := range []string{"/api/v1/config/", "/api/v1/zones", "/api/v1/firewall/", "/api/v1/services/proxy/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return path == "/api/v1/interfaces" || path == "/api/v1/interfaces/assign" ||
		(strings.HasPrefix(path, "/api/v1/interfaces/") && path != "/api/v1/interfaces/reconcile")
}
