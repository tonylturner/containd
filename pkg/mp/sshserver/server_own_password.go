// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type ownPasswordResult int

const (
	ownPasswordSkipped ownPasswordResult = iota
	ownPasswordChanged
	ownPasswordFailed
)

// changeOwnPassword changes the logged-in account's password after it
// confirms the current one, as the web change does, so a session opened with
// a key cannot set a password without knowing the old one. The store limits
// wrong current passwords per account. A blank answer skips the change. path
// names the console path in audit records. Callers refuse in lab mode before
// calling (users.CheckPasswordChange).
func (s *interactiveSession) changeOwnPassword(path, currentPrompt, newPrompt string) ownPasswordResult {
	current, ok := s.askSecret(currentPrompt)
	if !ok {
		return ownPasswordFailed
	}
	if strings.TrimSpace(current) == "" {
		return ownPasswordSkipped
	}
	u, err := s.server.opts.UserStore.GetByUsername(s.ctx, s.username)
	if err != nil || u == nil {
		s.writeLn("error: failed to load user")
		return ownPasswordFailed
	}
	if err := s.server.opts.UserStore.CheckCurrentPassword(s.ctx, u.ID, current, time.Now()); err != nil {
		detail, record, refused := users.Refusal(err)
		if !refused {
			s.writeLn("error: failed to check the current password")
			return ownPasswordFailed
		}
		if record {
			s.writeAudit(audit.Record{Action: "auth.password.change", Target: s.username, Result: "denied", Detail: path + ": " + detail})
		}
		s.writeLn("error: " + err.Error())
		return ownPasswordFailed
	}
	pw, ok := s.askNewPassword(newPrompt)
	if !ok {
		return ownPasswordFailed
	}
	if pw == "" {
		return ownPasswordSkipped
	}
	if err := s.server.opts.UserStore.SetPassword(s.ctx, u.ID, pw); err != nil {
		s.writeLn("error: " + err.Error())
		return ownPasswordFailed
	}
	s.writeAudit(audit.Record{Action: "auth.password.change", Target: s.username, Detail: path})
	return ownPasswordChanged
}
