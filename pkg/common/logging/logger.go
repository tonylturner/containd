// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package logging

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

// NewService returns a zap SugaredLogger for the named service with stdout output.
// It respects CONTAIND_LOG_LEVEL and CONTAIND_LOG_LEVEL_<SERVICE> environment variables.
// If syslog initialization fails, it keeps stdout logging and reports the failure
// once to stderr, regardless of the configured log level.
func NewService(name string) *zap.SugaredLogger {
	l, err := NewZap(name, "daemon", Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "containd: service %q syslog initialization failed; continuing with stdout: %v\n", name, err)
	}
	return l
}
