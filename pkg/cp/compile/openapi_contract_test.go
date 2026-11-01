// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"os"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"gopkg.in/yaml.v3"
)

func TestOpenAPIOrderedForwardSchemas(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type schema struct {
		Properties map[string]any `yaml:"properties"`
	}
	var document struct {
		Components struct {
			Schemas map[string]schema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for name, fields := range map[string][]string{
		"RulesSnapshot": {"AdmissionParity", "ForwardMatches", "LocalIPv4ByDevice"},
		"FirewallRule":  {"viaForwards"}, "PortForward": {"listenAddress"},
		"RulesEntry": {"ViaForwards"}, "RulesPortForward": {"ListenAddress"},
	} {
		for _, field := range fields {
			if _, ok := document.Components.Schemas[name].Properties[field]; !ok {
				t.Errorf("%s missing %s", name, field)
			}
		}
	}
	fields := document.Components.Schemas["ForwardMatch"].Properties
	typ := reflect.TypeFor[rules.ForwardMatch]()
	if len(fields) != typ.NumField() {
		t.Fatal("ForwardMatch schema field count drift")
	}
	for i := range typ.NumField() {
		if _, ok := fields[typ.Field(i).Name]; !ok {
			t.Errorf("missing forward field %s", typ.Field(i).Name)
		}
	}
	// The internal contract uses exported field names, the persisted one lower camel case.
	if _, ok := reflect.TypeFor[config.PortForward]().FieldByName("ListenAddress"); !ok {
		t.Fatal("config listen address absent")
	}
}
