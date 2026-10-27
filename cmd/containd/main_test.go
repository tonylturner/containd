// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestLoopbackManagementURL(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"", "http://127.0.0.1:8080"},
		{"  ", "http://127.0.0.1:8080"},
		{"10.0.0.5:9000", "http://127.0.0.1:9000"},
		{"[::1]:9001", "http://127.0.0.1:9001"},
		{"9000", ""},
	} {
		t.Setenv(config.EnvManagementHTTPAddr, tc.env)
		got, err := loopbackManagementURL()
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Errorf("%s=%q: url=%q err=%v, want %q", config.EnvManagementHTTPAddr, tc.env, got, err, tc.want)
		}
	}
}
