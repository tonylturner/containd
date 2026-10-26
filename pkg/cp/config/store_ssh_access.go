// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
)

// SSHRuntimePolicy reports effective authentication policy, not saved intent.
type SSHRuntimePolicy struct {
	AllowPassword       bool
	PasswordSource      string
	AuthorizedKeysDir   string
	HostKeyRotationDays int
}

// SetSSHRuntimePolicyReader registers management's runtime policy resolver.
func (s *SQLiteStore) SetSSHRuntimePolicyReader(read func(context.Context) (SSHRuntimePolicy, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshRuntimePolicyReader = read
}

func (s *SQLiteStore) SSHRuntimePolicy(ctx context.Context) (SSHRuntimePolicy, error) {
	s.mu.Lock()
	read := s.sshRuntimePolicyReader
	s.mu.Unlock()
	if read == nil {
		return SSHRuntimePolicy{}, errors.New("SSH runtime policy unavailable")
	}
	// The resolver loads running state itself; do not hold the store mutex.
	return read(ctx)
}

// SetSSHAccessValidator supplies live admin/key validation before management
// accepts candidate writes. The callback must not call config Store methods.
// It is intentionally separate from boot validation: persisted password
// disables remain authoritative even if keys subsequently disappear.
func (s *SQLiteStore) SetSSHAccessValidator(validate func(context.Context, SSHConfig) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshAccessValidator = validate
}

// validateSSHAccessLocked runs on staging and promotion, rechecking external
// key/user state even when the candidate was already validated.
func (s *SQLiteStore) validateSSHAccessLocked(ctx context.Context, cfg *Config) error {
	if cfg.System.SSH.AllowPassword == nil || *cfg.System.SSH.AllowPassword {
		return nil
	}
	if s.sshAccessValidator == nil {
		return &ValidationError{errors.New("ssh.allowPassword=false requires a usable admin authorized key; admin key validation is unavailable")}
	}
	if err := s.sshAccessValidator(ctx, cfg.System.SSH); err != nil {
		return &ValidationError{err}
	}
	return nil
}
