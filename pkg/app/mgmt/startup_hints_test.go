// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestPrintStartupHints(t *testing.T) {
	t.Parallel()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core).Sugar()

	printStartupHints(logger, ":8080", "127.0.0.1:8080", ":8443", "127.0.0.1:8443", true, true, ":2222", true)

	foundLogin := false
	foundSSH := false
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, "Initial login") {
			foundLogin = true
		}
		if strings.Contains(entry.Message, "SSH CLI") {
			foundSSH = true
		}
	}
	if !foundLogin || !foundSSH {
		t.Fatalf("startup hints missing expected log lines: login=%v ssh=%v", foundLogin, foundSSH)
	}
}
