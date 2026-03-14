// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package conntrack

import (
	"context"
	"strings"
	"testing"
)

func TestUnsupportedPlatformHelpers(t *testing.T) {
	t.Parallel()

	entries, err := List(10)
	if err == nil || !strings.Contains(err.Error(), "only available on Linux") {
		t.Fatalf("List error = %v, want unsupported-platform error", err)
	}
	if entries != nil {
		t.Fatalf("List entries = %#v, want nil", entries)
	}

	err = Delete(context.Background(), DeleteRequest{})
	if err == nil || !strings.Contains(err.Error(), "only available on Linux") {
		t.Fatalf("Delete error = %v, want unsupported-platform error", err)
	}
}
