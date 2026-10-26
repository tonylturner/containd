// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"fmt"
	"sync"

	"github.com/tonylturner/containd/pkg/common/labmode"
)

type actingSessionKey struct{}

// WithActingSession records the session that is making a request. A password
// or MFA change made under this context keeps that session when it belongs to
// the changed account, and revokes every other session of the account.
func WithActingSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, actingSessionKey{}, sessionID)
}

func actingSession(ctx context.Context) string {
	id, _ := ctx.Value(actingSessionKey{}).(string)
	return id
}

// revocationHub fans revoked session IDs out to in-process subscribers, such
// as the SSH server, which closes connections that hold a revoked session.
type revocationHub struct {
	mu   sync.Mutex
	next int
	subs map[int]func([]string)
}

func (h *revocationHub) subscribe(fn func([]string)) func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs == nil {
		h.subs = make(map[int]func([]string))
	}
	id := h.next
	h.next++
	h.subs[id] = fn
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.subs, id)
	}
}

func (h *revocationHub) publish(ids []string) {
	if len(ids) == 0 {
		return
	}
	h.mu.Lock()
	subs := make([]func([]string), 0, len(h.subs))
	for _, fn := range h.subs {
		subs = append(subs, fn)
	}
	h.mu.Unlock()
	for _, fn := range subs {
		fn(ids)
	}
}

// SubscribeSessionRevocations calls fn with the IDs of sessions that a
// credential change revoked or an account deletion removed. The returned
// function ends the subscription.
func (s *SQLiteStore) SubscribeSessionRevocations(fn func(sessionIDs []string)) func() {
	return s.revocations.subscribe(fn)
}

// revokeOtherSessions revokes the user's active sessions except the acting
// session from ctx. Lab mode pins credentials and keeps sessions unchanged.
func revokeOtherSessions(ctx context.Context, db userQuerier, userID string) ([]string, error) {
	if labmode.Enabled() {
		return nil, nil
	}
	keep := actingSession(ctx)
	ids, err := activeSessionIDs(ctx, db, userID, keep)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0 AND id<>?`, userID, keep); err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}
	return ids, nil
}

func activeSessionIDs(ctx context.Context, db userQuerier, userID, except string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM sessions WHERE user_id=? AND revoked=0 AND id<>?`, userID, except)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return ids, nil
}
