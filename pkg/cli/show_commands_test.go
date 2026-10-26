// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestShowInterfacesMode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		iface config.Interface
		want  string
	}{
		{name: "external", want: "external"},
		{name: "implicit static", iface: config.Interface{Addresses: []string{"192.0.2.1/24"}}, want: "static"},
		{name: "explicit static", iface: config.Interface{AddressMode: "static"}, want: "static"},
		{name: "dhcp", iface: config.Interface{AddressMode: "dhcp"}, want: "dhcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iface := tc.iface
			iface.Name = "test-iface"
			iface.Device = "nonexistent-test-device"
			iface.Zone = "test-zone"
			store := &memStore{cfg: &config.Config{Interfaces: []config.Interface{iface}}}
			client := &dispatchHTTPClient{
				t: t,
				handlers: map[string]func(*http.Request) (*http.Response, error){
					"GET /api/v1/interfaces": func(*http.Request) (*http.Response, error) {
						return jsonHTTPResponse(http.StatusOK, []config.Interface{iface}, nil), nil
					},
					"GET /api/v1/interfaces/state": func(*http.Request) (*http.Response, error) {
						return jsonHTTPResponse(http.StatusOK, []config.InterfaceState{}, nil), nil
					},
				},
			}
			api := &API{BaseURL: "http://localhost", Client: client}
			for name, command := range map[string]Command{
				"store": showInterfaces(store),
				"api":   showInterfacesAPI(api),
			} {
				t.Run(name, func(t *testing.T) {
					var out bytes.Buffer
					if err := command(context.Background(), &out, nil); err != nil {
						t.Fatal(err)
					}
					lines := strings.Split(out.String(), "\n")
					var mode string
					for _, line := range lines {
						fields := strings.Fields(line)
						if len(fields) >= 4 && fields[0] == iface.Name {
							mode = fields[3]
						}
					}
					if mode != tc.want {
						t.Fatalf("MODE = %q, want %q; output:\n%s", mode, tc.want, out.String())
					}
				})
			}
		})
	}
}
