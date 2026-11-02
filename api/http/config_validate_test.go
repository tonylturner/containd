// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestValidateRedactedManagedOpenVPN(t *testing.T) {
	for _, change := range []string{"management", "replace secret", "invalid client"} {
		t.Run(change, func(t *testing.T) {
			store := stageStore(t)
			ctx := context.Background()
			// The running config has no VPN credentials: restoration must use
			// the candidate, just as a full-document candidate write does.
			if err := testMutateCandidate(store, ctx, func(cfg *config.Config) error {
				cfg.Services.VPN.OpenVPN = config.OpenVPNConfig{
					Enabled: true, Mode: "client",
					Managed: &config.OpenVPNManagedClientConfig{
						Remote: "vpn.example.test", Username: "operator", Password: "password-material",
						CA: "ca-material", Cert: "cert-material", Key: "key-material",
					},
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			server := NewServer(store, nil)
			read := requestStage(t, server, "GET", "/config/candidate", nil)
			if read.Code != http.StatusOK || strings.Contains(read.Body.String(), "-material") {
				t.Fatalf("redacted read: %d %s", read.Code, read.Body)
			}
			var submitted config.Config
			if err := json.Unmarshal(read.Body.Bytes(), &submitted); err != nil {
				t.Fatal(err)
			}
			submitted.System.Hostname = "management-edit"
			wantStatus := http.StatusOK
			switch change {
			case "replace secret":
				submitted.Services.VPN.OpenVPN.Managed.Key = "replacement-material"
			case "invalid client":
				submitted.Services.VPN.OpenVPN.Managed.Remote = ""
				wantStatus = http.StatusBadRequest
			}
			before, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil {
				t.Fatal(err)
			}
			validated := requestStage(t, server, "POST", "/config/validate", submitted)
			if validated.Code != wantStatus || strings.Contains(validated.Body.String(), "-material") {
				t.Fatalf("validate: %d %s", validated.Code, validated.Body)
			}
			after, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("validation changed configuration or revision")
			}
			staged := requestStage(t, server, "POST", "/config/candidate", submitted)
			if staged.Code != wantStatus {
				t.Fatalf("stage disagrees with validate: %d %s", staged.Code, staged.Body)
			}
			if wantStatus != http.StatusOK {
				return
			}
			after, err = store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil {
				t.Fatal(err)
			}
			want := *before.Candidate.Services.VPN.OpenVPN.Managed
			if change == "replace secret" {
				want.Key = "replacement-material"
			}
			if *after.Candidate.Services.VPN.OpenVPN.Managed != want || after.Candidate.System.Hostname != "management-edit" {
				t.Fatal("candidate write lost secrets or management edits")
			}
		})
	}
}
