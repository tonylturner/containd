// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package main

import (
	"context"
	"errors"
	"testing"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want int
	}{
		{name: "nil error", ctx: context.Background(), want: 0},
		{name: "canceled by signal", ctx: canceledContext(t), err: context.Canceled, want: 0},
		{name: "canceled without signal", ctx: context.Background(), err: context.Canceled, want: 1},
		{name: "real error", ctx: context.Background(), err: errors.New("run failed"), want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.ctx, tt.err); got != tt.want {
				t.Errorf("exitCode(%v, %v) = %d, want %d", tt.ctx, tt.err, got, tt.want)
			}
		})
	}
}

func canceledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
