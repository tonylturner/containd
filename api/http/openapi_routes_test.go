// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// TestOpenAPIRoutes compares the public wire contract with the production
// constructor, including delegated audit and optional identity registration.
// No /api/v1 operations are excluded. Non-versioned /metrics is outside this
// specification's /api/v1 server base.
func TestOpenAPIRoutes(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Servers) != 1 || spec.Servers[0].URL != "/api/v1" {
		t.Fatal("OpenAPI server base must be /api/v1")
	}
	documented := make(map[string]bool)
	for path, item := range spec.Paths {
		for method := range item {
			switch method {
			case "get", "put", "post", "delete", "options", "head", "patch", "trace":
				documented[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	if len(documented) == 0 {
		t.Fatal("OpenAPI contains no operations")
	}

	// The route-inventory helper omits the audit store. Exercise it below,
	// and use the same production constructor with audit enabled for parity.
	full := NewServerWithEngineAndServices(
		&mockStore{}, &mockAuditStore{}, newRuntimeMockEngine(),
		routeInventoryServices{}, newMockUserStore(),
	)
	registered := openAPIOperations(full)
	for operation := range registered {
		if !documented[operation] {
			t.Errorf("registered operation missing from OpenAPI: %s", operation)
		}
	}
	for operation := range documented {
		if !registered[operation] {
			t.Errorf("OpenAPI operation not registered: %s", operation)
		}
	}
	// Disabled optional integrations must not introduce undocumented routes.
	for name, router := range map[string]*gin.Engine{
		"minimal":   NewServer(&mockStore{}, nil),
		"inventory": newRouteInventoryServer(t),
	} {
		for operation := range openAPIOperations(router) {
			if !documented[operation] {
				t.Errorf("%s server operation missing from OpenAPI: %s", name, operation)
			}
		}
	}
	t.Logf("compared %d registered /api/v1 operations with %d OpenAPI operations", len(registered), len(documented))
}

func openAPIOperations(router *gin.Engine) map[string]bool {
	operations := make(map[string]bool)
	for _, route := range router.Routes() {
		path, ok := strings.CutPrefix(route.Path, "/api/v1/")
		if !ok {
			continue
		}
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, ":") {
				parts[i] = "{" + strings.TrimPrefix(part, ":") + "}"
			}
		}
		operations[route.Method+" /"+strings.Join(parts, "/")] = true
	}
	return operations
}
