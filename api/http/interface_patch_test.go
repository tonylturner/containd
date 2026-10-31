// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func interfacePatchStore(t *testing.T) *config.SQLiteStore {
	t.Helper()
	store := stageStore(t)
	enabled, disabled := true, false
	err := store.MutateCandidate(context.Background(), func(cfg *config.Config) error {
		cfg.Interfaces = append(cfg.Interfaces, config.Interface{
			Name: "patch0", Alias: "Plant VLAN", Device: "eth9",
			Type: "vlan", Parent: "eth8", VLANID: 123, Members: []string{"eth7"},
			Zone: "spare", AddressMode: "static", Addresses: []string{"192.0.2.2/24"},
			Gateway: "192.0.2.1",
			Access:  config.InterfaceAccess{Mgmt: &enabled, HTTP: &disabled, HTTPS: &enabled, SSH: &disabled},
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestInterfacePatchMerge(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		change     func(*config.Interface)
	}{
		{"empty object", `{}`, func(*config.Interface) {}},
		{"alias only", `{"alias":"Renamed"}`, func(i *config.Interface) { i.Alias = "Renamed" }},
		{"addresses only", `{"addresses":["198.51.100.2/24"]}`, func(i *config.Interface) {
			i.Addresses = []string{"198.51.100.2/24"}
		}},
		{"empty alias", `{"alias":""}`, func(i *config.Interface) { i.Alias = "" }},
		{"null alias", `{"alias":null}`, func(i *config.Interface) { i.Alias = "" }},
		{"empty device and zone", `{"device":"","zone":""}`, func(i *config.Interface) {
			i.Device, i.Zone = "", ""
		}},
		{"null device and zone", `{"device":null,"zone":null}`, func(i *config.Interface) {
			i.Device, i.Zone = "", ""
		}},
		{"empty arrays", `{"members":[],"addresses":[]}`, func(i *config.Interface) {
			// Empty slices are omitted when the store serializes the candidate.
			i.Members, i.Addresses = nil, nil
		}},
		{"null arrays", `{"members":null,"addresses":null}`, func(i *config.Interface) {
			i.Members, i.Addresses = nil, nil
		}},
		{"empty addressing", `{"addressMode":"","gateway":""}`, func(i *config.Interface) {
			i.AddressMode, i.Gateway = "", ""
		}},
		{"null addressing", `{"addressMode":null,"gateway":null}`, func(i *config.Interface) {
			i.AddressMode, i.Gateway = "", ""
		}},
		{"VLAN to physical", `{"type":"physical","parent":"","vlanId":0}`, func(i *config.Interface) {
			i.Type, i.Parent, i.VLANID = "physical", "", 0
		}},
		{"empty VLAN fields", `{"type":"","parent":"","vlanId":0}`, func(i *config.Interface) {
			i.Type, i.Parent, i.VLANID = "", "", 0
		}},
		{"null VLAN fields", `{"type":null,"parent":null,"vlanId":null}`, func(i *config.Interface) {
			i.Type, i.Parent, i.VLANID = "", "", 0
		}},
		{"empty access", `{"access":{}}`, func(i *config.Interface) { i.Access = config.InterfaceAccess{} }},
		{"null access", `{"access":null}`, func(i *config.Interface) { i.Access = config.InterfaceAccess{} }},
		{"false access replaces object", `{"access":{"mgmt":false}}`, func(i *config.Interface) {
			disabled := false
			i.Access = config.InterfaceAccess{Mgmt: &disabled}
		}},
		{"null access flags", `{"access":{"mgmt":null,"http":null,"https":null,"ssh":null}}`, func(i *config.Interface) {
			i.Access = config.InterfaceAccess{}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := interfacePatchStore(t)
			ctx := context.Background()
			want, err := store.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			tt.change(&want.Interfaces[len(want.Interfaces)-1])
			server := NewServer(store, nil)
			req := authedRequest(http.MethodPatch, "/api/v1/interfaces/patch0", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("PATCH: %d %s", rec.Code, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "staged")
			got, err := store.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Interfaces, want.Interfaces) {
				t.Fatalf("stored interfaces:\n got: %#v\nwant: %#v", got.Interfaces, want.Interfaces)
			}
		})
	}
}

func TestInterfacePatchRejected(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
		status           int
	}{
		{"unknown interface", "missing", `{"alias":"Renamed"}`, http.StatusNotFound},
		{"null payload", "patch0", `null`, http.StatusBadRequest},
		{"array payload", "patch0", `[]`, http.StatusBadRequest},
		{"malformed JSON", "patch0", `{`, http.StatusBadRequest},
		{"wrong field type", "patch0", `{"vlanId":"invalid"}`, http.StatusBadRequest},
		{"invalid VLAN", "patch0", `{"vlanId":0}`, http.StatusBadRequest},
		{"empty name", "patch0", `{"name":""}`, http.StatusBadRequest},
		{"null name", "patch0", `{"name":null}`, http.StatusBadRequest},
		{"invalid zone", "patch0", `{"zone":"missing"}`, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := interfacePatchStore(t)
			ctx := context.Background()
			before, err := store.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			req := authedRequest(http.MethodPatch, "/api/v1/interfaces/"+tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			NewServer(store, nil).ServeHTTP(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("PATCH: %d %s, want %d", rec.Code, rec.Body, tt.status)
			}
			after, err := store.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected PATCH changed candidate")
			}
		})
	}
}

func TestInterfacePatchRequiresAdmin(t *testing.T) {
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "test-auditor")
	store := interfacePatchStore(t)
	req := authedRequest(http.MethodPatch, "/api/v1/interfaces/patch0", strings.NewReader(`{"alias":"Renamed"}`))
	req.Header.Set("Authorization", "Bearer test-auditor")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewServer(store, nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PATCH: %d %s, want 403", rec.Code, rec.Body)
	}
}
