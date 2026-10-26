// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPasswordAndTLSOpenAPIResponses(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]struct {
			Post struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema struct {
							Ref string `yaml:"$ref"`
						} `yaml:"schema"`
					} `yaml:"content"`
				} `yaml:"responses"`
			} `yaml:"post"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/me/password", "/users/{id}/password", "/system/tls/cert"} {
		t.Run(path, func(t *testing.T) {
			codes := []string{"400", "401", "403", "404", "413", "429", "503"}
			responses := spec.Paths[path].Post.Responses
			if path == "/system/tls/cert" {
				codes = []string{"409"}
			} else if len(responses) != len(codes)+1 {
				t.Errorf("got %d responses; want 200 and %v", len(responses), codes)
			}
			if got := responses["200"].Content["application/json"].Schema.Ref; got != "#/components/schemas/StatusResponse" {
				t.Errorf("200 schema = %q; want StatusResponse", got)
			}
			for _, code := range codes {
				if got := responses[code].Content["application/json"].Schema.Ref; got != "#/components/schemas/ErrorResponse" {
					t.Errorf("%s schema = %q; want ErrorResponse", code, got)
				}
			}
		})
	}
}
