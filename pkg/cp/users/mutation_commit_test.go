// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package users

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMutationCommitFailureReleasesConnection(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u, err := s.Create(ctx, User{Username: "commit-user", Role: "admin"}, storeCredential("commit-user"))
	if err != nil {
		t.Fatal(err)
	}
	firstName := "changed"

	tests := []struct {
		name, trigger string
		run           func() error
	}{
		{
			name:    "credential update",
			trigger: `CREATE TRIGGER fail_commit AFTER UPDATE ON users BEGIN INSERT INTO commit_fault VALUES ('missing-user'); END;`,
			run: func() error {
				return s.SetTOTP(ctx, u.ID, "BASE32SECRET")
			},
		},
		{
			name:    "user profile update",
			trigger: `CREATE TRIGGER fail_commit AFTER UPDATE ON users BEGIN INSERT INTO commit_fault VALUES ('missing-user'); END;`,
			run: func() error {
				_, err := s.Update(ctx, u.ID, Patch{FirstName: &firstName})
				return err
			},
		},
		{
			name:    "MFA challenge creation",
			trigger: `CREATE TRIGGER fail_commit AFTER INSERT ON mfa_challenges BEGIN INSERT INTO commit_fault VALUES ('missing-user'); END;`,
			run: func() error {
				current, err := s.GetByID(ctx, u.ID)
				if err != nil {
					return err
				}
				_, err = s.CreateMFAChallenge(ctx, current, MFAChallengeLogin, time.Now().Add(time.Hour))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.db.Exec(`CREATE TABLE commit_fault (id TEXT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tt.trigger); err != nil {
				t.Fatal(err)
			}
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
				t.Fatalf("expected commit failure, got %v", err)
			}
			if _, err := s.db.Exec(`DROP TRIGGER fail_commit; DROP TABLE commit_fault`); err != nil {
				t.Fatalf("connection unavailable after failed commit: %v", err)
			}
			if _, err := s.GetByID(ctx, u.ID); err != nil {
				t.Fatalf("store unavailable after failed commit: %v", err)
			}
		})
	}
}
