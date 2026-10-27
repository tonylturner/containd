// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
)

// TestCommitCarriesEngineServiceWarnings: a services apply the engine
// accepted with warnings, such as an AV backend that is still starting,
// commits and reports them next to the infrastructure warnings; a failed
// apply stays a warning of its own.
func TestCommitCarriesEngineServiceWarnings(t *testing.T) {
	const pending = "AV backend is still starting: clamd not ready; scanning is pending until it is ready"
	for _, tc := range []struct {
		name     string
		warnings []string
		err      error
		want     []string
	}{
		{"applied", nil, nil, nil},
		{"pending", []string{pending}, nil, []string{"services: " + pending}},
		{"failed", nil, errors.New("engine services status 503: AV service apply failed"),
			[]string{"services: engine services status 503: AV service apply failed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := stageStore(t)
			engine := &mockEngine{svcWarnings: tc.warnings, svcErr: tc.err}
			server := NewServerWithEngine(store, &mockAuditStore{}, engine)
			rec := requestStage(t, server, http.MethodPost, "/config/commit", nil)
			if rec.Code != http.StatusOK || !engine.applied {
				t.Fatalf("status=%d applied=%v body=%s", rec.Code, engine.applied, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "committed")
			if got := rec.Header().Values("X-Containd-Warnings"); !slices.Equal(got, tc.want) {
				t.Fatalf("X-Containd-Warnings = %q, want %q", got, tc.want)
			}
			replayed, err := ApplyRunningConfig(context.Background(), store, engine, nil)
			if err != nil || !slices.Equal(replayed, tc.want) {
				t.Fatalf("replay warnings = %q err=%v, want %q", replayed, err, tc.want)
			}
		})
	}
}
