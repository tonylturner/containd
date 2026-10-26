// SPDX-License-Identifier: Apache-2.0
package mgmtpath

import (
	"reflect"
	"testing"
)

func TestResolveBindings(t *testing.T) {
	for _, tt := range []struct {
		name     string
		allowed  []string
		denied   []string
		live     []string
		want     []string
		recovery bool
	}{
		{"bound", []string{"eth1", "stale"}, nil, []string{"eth0", "eth1"}, []string{"eth1"}, false},
		{"unbound", nil, nil, []string{"eth0"}, []string{"eth0"}, true},
		{"stale", []string{"stale"}, nil, []string{"eth0"}, []string{"eth0"}, true},
		{"disabled excluded", nil, []string{"eth0"}, []string{"eth0", "eth1"}, []string{"eth1"}, true},
		{"none safe", nil, []string{"eth0"}, []string{"eth0"}, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, recovery := ResolveBindings(tt.allowed, tt.denied, tt.live)
			if !reflect.DeepEqual(got, tt.want) || recovery != tt.recovery {
				t.Fatalf("got %v %v want %v %v", got, recovery, tt.want, tt.recovery)
			}
		})
	}
}
