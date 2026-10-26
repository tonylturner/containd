// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// routingPostClient serves current as the routing config and records the
// routing config the quick start posts.
func routingPostClient(t *testing.T, current config.RoutingConfig, posted *config.RoutingConfig) *dispatchHTTPClient {
	return &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/routing": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, current, nil), nil
		},
		"POST /api/v1/routing": func(req *http.Request) (*http.Response, error) {
			*posted = decodeJSONRequest[config.RoutingConfig](t, req)
			return jsonHTTPResponse(200, nil, nil), nil
		},
	}}
}

func TestApplyQuickstartRoutingReplacesGatewayAndDefaultRoute(t *testing.T) {
	t.Parallel()

	other := config.Gateway{Name: "lab-gw", Address: "198.51.100.1", Iface: "eth2"}
	lab := config.StaticRoute{Dst: "198.18.0.0/15", Gateway: "lab-gw"}
	tableDefault := config.StaticRoute{Dst: "default", Gateway: "lab-gw", Table: 200}
	current := config.RoutingConfig{
		Gateways: []config.Gateway{other, {Name: quickstartGatewayName, Address: "192.0.2.254", Iface: "wan"}},
		Routes:   []config.StaticRoute{lab, tableDefault, {Dst: "0.0.0.0/0", Gateway: "192.0.2.254"}},
	}
	var posted config.RoutingConfig
	api := &API{BaseURL: "http://test", Client: routingPostClient(t, current, &posted)}

	if err := applyQuickstartRouting(context.Background(), api, "eth0", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}

	wantGateways := []config.Gateway{other, {
		Name: quickstartGatewayName, Address: "192.0.2.1", Iface: "eth0", Description: "Quick start: WAN default gateway",
	}}
	wantRoutes := []config.StaticRoute{lab, tableDefault, {Dst: "default", Gateway: quickstartGatewayName, Iface: "eth0"}}
	if !reflect.DeepEqual(posted.Gateways, wantGateways) {
		t.Fatalf("gateways = %#v, want %#v", posted.Gateways, wantGateways)
	}
	if !reflect.DeepEqual(posted.Routes, wantRoutes) {
		t.Fatalf("routes = %#v, want %#v", posted.Routes, wantRoutes)
	}
}

func TestApplyQuickstartRoutingAppendsGatewayAndDefaultRoute(t *testing.T) {
	t.Parallel()

	var posted config.RoutingConfig
	api := &API{BaseURL: "http://test", Client: routingPostClient(t, config.RoutingConfig{}, &posted)}

	if err := applyQuickstartRouting(context.Background(), api, "eth0", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}

	if len(posted.Gateways) != 1 || posted.Gateways[0].Name != quickstartGatewayName || posted.Gateways[0].Iface != "eth0" {
		t.Fatalf("gateways = %#v", posted.Gateways)
	}
	want := []config.StaticRoute{{Dst: "default", Gateway: quickstartGatewayName, Iface: "eth0"}}
	if !reflect.DeepEqual(posted.Routes, want) {
		t.Fatalf("routes = %#v, want %#v", posted.Routes, want)
	}
}
