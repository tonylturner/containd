// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"net"
	"syscall"
	"testing"
)

func TestIsRawSocketDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eperm", syscall.EPERM, true},
		{"eacces", syscall.EACCES, true},
		{"operror-eperm", &net.OpError{Op: "listen", Net: "ip4:icmp", Err: syscall.EPERM}, true},
		{"wrapped-hint", rawSocketHint(syscall.EPERM), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRawSocketDenied(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v (err=%v)", got, tc.want, tc.err)
			}
		})
	}
}

