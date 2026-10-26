// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestCredentialChangesRevokeOtherSessions(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	changes := map[string]func(*SQLiteStore, context.Context, string) error{
		"password": func(s *SQLiteStore, ctx context.Context, id string) error {
			return s.SetPassword(ctx, id, storeCredential("rotated"))
		},
		"totp enable": func(s *SQLiteStore, ctx context.Context, id string) error {
			return s.SetTOTP(ctx, id, "JBSWY3DPEHPK3PXP")
		},
		"totp disable": func(s *SQLiteStore, ctx context.Context, id string) error {
			return s.DisableTOTP(ctx, id)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			u, err := s.Create(ctx, User{Username: "owner", Role: "admin"}, storeCredential("owner"))
			if err != nil {
				t.Fatal(err)
			}
			other, err := s.Create(ctx, User{Username: "other", Role: "admin"}, storeCredential("other"))
			if err != nil {
				t.Fatal(err)
			}
			acting := mustSession(t, s, u.ID)
			stale := mustSession(t, s, u.ID)
			unrelated := mustSession(t, s, other.ID)
			var published [][]string
			unsubscribe := s.SubscribeSessionRevocations(func(ids []string) { published = append(published, ids) })
			defer unsubscribe()

			if err := change(s, WithActingSession(ctx, acting), u.ID); err != nil {
				t.Fatal(err)
			}
			assertRevoked(t, s, acting, false)
			assertRevoked(t, s, stale, true)
			assertRevoked(t, s, unrelated, false)
			if len(published) != 1 || !slices.Equal(published[0], []string{stale}) {
				t.Fatalf("published = %v, want [[%s]]", published, stale)
			}

		})
	}
}

func TestCredentialChangeByAnotherAccountRevokesAll(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	ctx := context.Background()
	admin, err := s.Create(ctx, User{Username: "admin", Role: "admin"}, storeCredential("admin"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Create(ctx, User{Username: "admin-set", Role: "view"}, storeCredential("admin-set"))
	if err != nil {
		t.Fatal(err)
	}
	adminSession := mustSession(t, s, admin.ID)
	first, second := mustSession(t, s, u.ID), mustSession(t, s, u.ID)
	for _, changeCtx := range []context.Context{WithActingSession(ctx, adminSession), ctx} {
		if err := s.DisableTOTP(changeCtx, u.ID); err != nil {
			t.Fatal(err)
		}
		assertRevoked(t, s, first, true)
		assertRevoked(t, s, second, true)
		assertRevoked(t, s, adminSession, false)
	}
}

func TestFailedCredentialChangeKeepsSessions(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	s := newTestStore(t)
	ctx := context.Background()
	current := storeCredential("keep")
	u, err := s.Create(ctx, User{Username: "keep", Role: "view"}, current)
	if err != nil {
		t.Fatal(err)
	}
	sess := mustSession(t, s, u.ID)
	for _, password := range []string{"weak", current} {
		if err := s.SetPassword(ctx, u.ID, password); !IsPasswordPolicyError(err) {
			t.Fatalf("SetPassword(%q) = %v, want a password policy error", password, err)
		}
	}
	if err := s.SetPassword(ctx, u.ID, current); !errors.Is(err, ErrPasswordReuse) {
		t.Fatalf("reuse = %v, want ErrPasswordReuse", err)
	}
	if err := s.SetTOTP(ctx, "missing", "JBSWY3DPEHPK3PXP"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetTOTP(missing) = %v", err)
	}
	assertRevoked(t, s, sess, false)
}

func TestLabModeCredentialChangeKeepsSessions(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.Create(ctx, User{Username: "lab", Role: "admin"}, storeCredential("lab"))
	if err != nil {
		t.Fatal(err)
	}
	sess := mustSession(t, s, u.ID)
	published := 0
	defer s.SubscribeSessionRevocations(func([]string) { published++ })()
	if err := s.SetTOTP(ctx, u.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	assertRevoked(t, s, sess, false)
	if published != 0 {
		t.Fatalf("lab mode published %d revocations", published)
	}
}

func TestDeletePublishesRemovedSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.Create(ctx, User{Username: "gone", Role: "view"}, storeCredential("gone"))
	if err != nil {
		t.Fatal(err)
	}
	sess := mustSession(t, s, u.ID)
	var published []string
	unsubscribe := s.SubscribeSessionRevocations(func(ids []string) { published = append(published, ids...) })
	if err := s.Delete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(published, []string{sess}) {
		t.Fatalf("published = %v", published)
	}
	unsubscribe()
	other, err := s.Create(ctx, User{Username: "after", Role: "view"}, storeCredential("after"))
	if err != nil {
		t.Fatal(err)
	}
	mustSession(t, s, other.ID)
	if err := s.Delete(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
	if len(published) != 1 {
		t.Fatalf("unsubscribed callback ran: %v", published)
	}
}

func mustSession(t *testing.T, s *SQLiteStore, userID string) string {
	t.Helper()
	sess, err := s.CreateSession(context.Background(), userID, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return sess.ID
}

func assertRevoked(t *testing.T, s *SQLiteStore, id string, want bool) {
	t.Helper()
	sess, err := s.GetSession(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Revoked != want {
		t.Fatalf("session %s revoked = %v, want %v", id, sess.Revoked, want)
	}
}
