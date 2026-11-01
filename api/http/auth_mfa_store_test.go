// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/cp/users"
)

// The mock covers handler routing only; durable replay, credential binding and
// concurrency are exercised against SQLite in the assurance tests.
type mockMFAChallenge struct {
	userID, purpose string
	expires         time.Time
}

func (m *mockUserStore) DisableTOTPWithGrace(_ context.Context, id string, now time.Time) error {
	u, ok := m.users[id]
	if !ok {
		return users.ErrNotFound
	}
	u.TOTPSecret = ""
	u.MFAEnabled = false
	u.MFAGraceUntil = nil
	if u.MFARequired {
		deadline := users.MFAGraceDeadline(now)
		u.MFAGraceUntil = &deadline
	}
	return nil
}

func (m *mockUserStore) CreateMFAChallenge(_ context.Context, u *users.StoredUser, purpose string, expires time.Time) (string, error) {
	if m.challenges == nil {
		m.challenges = make(map[string]mockMFAChallenge)
	}
	m.nextChallenge++
	id := fmt.Sprintf("challenge-%d", m.nextChallenge)
	m.challenges[id] = mockMFAChallenge{u.ID, purpose, expires}
	return id, nil
}

func (m *mockUserStore) checkChallenge(id, userID, purpose string, now time.Time) error {
	c, ok := m.challenges[id]
	if !ok || c.userID != userID || c.purpose != purpose || !now.Before(c.expires) {
		return users.ErrMFAChallenge
	}
	return nil
}

func (m *mockUserStore) RedeemLoginMFA(ctx context.Context, id, userID, code string, now time.Time) error {
	if err := m.checkChallenge(id, userID, users.MFAChallengeLogin, now); err != nil {
		return err
	}
	if err := m.AcceptTOTP(ctx, userID, code, now); err != nil {
		return err
	}
	delete(m.challenges, id)
	return nil
}

func (m *mockUserStore) RedeemEnrollMFA(ctx context.Context, id, userID, secret, code string, now time.Time) error {
	if err := m.checkChallenge(id, userID, users.MFAChallengeEnroll, now); err != nil {
		return err
	}
	if !users.ValidateTOTP(secret, code, now) {
		return users.ErrInvalidTOTP
	}
	delete(m.challenges, id)
	return m.SetTOTP(ctx, userID, secret)
}
