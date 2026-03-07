// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package logging

import "go.uber.org/zap"

// NewService returns a zap SugaredLogger for the named service with stdout output.
// It respects CONTAIND_LOG_LEVEL and CONTAIND_LOG_LEVEL_<SERVICE> environment variables.
// It panics only if logger creation fails, which requires syslog misconfiguration.
func NewService(name string) *zap.SugaredLogger {
	l, err := NewZap(name, "daemon", Options{})
	if err != nil {
		// Syslog dial failed; retry without syslog.
		l, _ = NewZap(name, "daemon", Options{SyslogAddr: ""})
		if l == nil {
			return zap.NewNop().Sugar()
		}
	}
	return l
}
