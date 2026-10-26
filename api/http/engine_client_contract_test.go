// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	engineclient "github.com/tonylturner/containd/api/engine"
)

// httpEngineClient is the engine client management runs with.
var httpEngineClient = (*engineclient.HTTPClient)(nil)

// engineClientInterfaces lists every interface the handlers type-assert on
// the engine client. Each conversion fails to compile when the engine HTTP
// client stops implementing that interface; TestEngineClientContractCoversAssertions
// fails when a handler asserts an interface missing from this table.
var engineClientInterfaces = map[string]any{
	"EngineClient":          EngineClient(httpEngineClient),
	"AnomalyClient":         AnomalyClient(httpEngineClient),
	"ConntrackClient":       ConntrackClient(httpEngineClient),
	"ConntrackKiller":       ConntrackKiller(httpEngineClient),
	"DHCPLeasesClient":      DHCPLeasesClient(httpEngineClient),
	"EventQueryClient":      EventQueryClient(httpEngineClient),
	"InventoryClient":       InventoryClient(httpEngineClient),
	"LearnClient":           LearnClient(httpEngineClient),
	"RuleCountersClient":    RuleCountersClient(httpEngineClient),
	"RulePreviewClient":     RulePreviewClient(httpEngineClient),
	"RulesetPreviewClient":  RulesetPreviewClient(httpEngineClient),
	"RuntimeHealthClient":   RuntimeHealthClient(httpEngineClient),
	"SignaturesClient":      SignaturesClient(httpEngineClient),
	"SimulationClient":      SimulationClient(httpEngineClient),
	"StatsClient":           StatsClient(httpEngineClient),
	"TelemetryClient":       TelemetryClient(httpEngineClient),
	"WireGuardStatusClient": WireGuardStatusClient(httpEngineClient),
}

// TestEngineClientContractCoversAssertions parses the package's handlers and
// requires every type assertion on an EngineClient parameter to name an
// interface in engineClientInterfaces, so a new optional capability cannot
// ship without an engine implementation.
func TestEngineClientContractCoversAssertions(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	asserted := map[string][]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			params := engineClientParams(fn.Type)
			if len(params) == 0 {
				return false
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ta, ok := n.(*ast.TypeAssertExpr)
				if !ok || ta.Type == nil {
					return true
				}
				x, ok := ta.X.(*ast.Ident)
				if !ok || !params[x.Name] {
					return true
				}
				iface, ok := ta.Type.(*ast.Ident)
				if !ok {
					t.Errorf("%s: engine client asserted to non-local type %s", fset.Position(ta.Pos()), types.ExprString(ta.Type))
					return true
				}
				asserted[iface.Name] = append(asserted[iface.Name], fset.Position(ta.Pos()).String())
				return true
			})
			return false
		})
	}
	if len(asserted) < 10 {
		t.Fatalf("found assertions for only %d interfaces; the scan no longer matches the handlers", len(asserted))
	}
	var missing []string
	for name, sites := range asserted {
		if _, ok := engineClientInterfaces[name]; !ok {
			missing = append(missing, name+" at "+strings.Join(sites, ", "))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("engine client asserted to %s, which engineClientInterfaces does not check against the engine HTTP client", m)
	}
}

// engineClientParams returns the names of fn's parameters typed EngineClient.
func engineClientParams(ft *ast.FuncType) map[string]bool {
	names := map[string]bool{}
	for _, field := range ft.Params.List {
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "EngineClient" {
			for _, n := range field.Names {
				names[n.Name] = true
			}
		}
	}
	return names
}
