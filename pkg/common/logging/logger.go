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
	return NewServiceWithOptions(name, "daemon", Options{})
}

// NewServiceWithOptions returns a service logger with the configured local sinks.
// If syslog initialization fails, it preserves stdout and configured file logging
// and reports the failure once to stderr, regardless of the configured log level.
func NewServiceWithOptions(name, facility string, opts Options) *zap.SugaredLogger {
	l, err := NewZap(name, facility, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "containd: service %q syslog initialization failed; continuing with local logging: %v\n", name, err)
	}
	return l
}
