// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/profile"
	"golang.org/x/crypto/bcrypt"
)

// Profile selection is process-wide and immutable. Exercise the real public
// entry points in a separate process rather than changing production globals.
func TestStrictBootstrap(t *testing.T) {
	if os.Getenv("CONTAIND_USERS_STRICT_TEST") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStrictBootstrap$", "-test.v")
		cmd.Env = append(os.Environ(), "CONTAIND_USERS_STRICT_TEST=1", "CONTAIND_PROFILE=strict")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("strict subprocess: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	if p, err := profile.Load(); err != nil || p != profile.Strict {
		t.Fatalf("load strict: %q, %v", p, err)
	}
	t.Setenv("CONTAIND_LAB_MODE", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
	t.Run("FreshReissueRetire", testStrictFreshReissueRetire)
	t.Run("RotateAndReissueEveryAccount", testStrictRotateAccounts)
	t.Run("MissingNamedAdmin", testStrictMissingNamedAdmin)
	t.Run("Reset", testStrictReset)
	t.Run("CommitFailure", testStrictCommitFailure)
}

func bootstrapEvents(t *testing.T, s *SQLiteStore) *[]BootstrapEvent {
	t.Helper()
	events := new([]BootstrapEvent)
	s.SetBootstrapObserver(func(event BootstrapEvent) {
		// Reading from this single-connection store also proves publication is
		// outside the transaction. Check the committed state, not just timing.
		u, err := s.GetByID(context.Background(), event.UserID)
		if err != nil {
			t.Fatalf("observer read: %v", err)
		}
		if event.Kind == BootstrapIssued {
			if !u.MustChangePassword || event.Generation < 1 ||
				bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(event.Password)) != nil {
				t.Fatal("observer saw an uncommitted or invalid issuance")
			}
			if err := validatePassword(event.Password); err != nil {
				t.Fatalf("generated password policy: %v", err)
			}
			var generation int64
			var reason string
			var issued int64
			if err := s.db.QueryRow(`SELECT generation, reason, issued_at FROM bootstrap_pending WHERE user_id=?`, u.ID).
				Scan(&generation, &reason, &issued); err != nil {
				t.Fatal(err)
			}
			if generation != event.Generation || reason != event.Reason || issued <= 0 {
				t.Fatal("observer metadata does not match committed issuance")
			}
		} else if event.Kind == BootstrapRetired {
			if u.MustChangePassword || event.Password != "" {
				t.Fatal("invalid retirement event")
			}
			assertPendingCount(t, s, 0)
		} else {
			t.Fatalf("unknown event kind: %q", event.Kind)
		}
		*events = append(*events, event)
	})
	return events
}

func assertPendingCount(t *testing.T, s *SQLiteStore, want int) {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bootstrap_pending`).Scan(&count); err != nil || count != want {
		t.Fatalf("pending count=%d want=%d: %v", count, want, err)
	}
}

func mustEnsure(t *testing.T, s *SQLiteStore) {
	t.Helper()
	if err := s.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func testStrictFreshReissueRetire(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	events := bootstrapEvents(t, s)
	mustEnsure(t, s)
	if len(*events) != 1 || (*events)[0].Reason != "seed" || (*events)[0].Generation != 1 {
		t.Fatalf("expected one initial seed, got %d events", len(*events))
	}
	first := (*events)[0]
	u, err := s.GetByID(ctx, first.UserID)
	if err != nil || u.Role != "admin" || u.Username != "containd" || u.CredentialVersion != 1 ||
		bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("containd")) == nil {
		t.Fatalf("invalid fresh strict admin: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	events = bootstrapEvents(t, s)
	mustEnsure(t, s)
	if len(*events) != 1 || (*events)[0].Reason != "reissue" || (*events)[0].Generation != 2 {
		t.Fatalf("expected one reissue, got %d events", len(*events))
	}
	second := (*events)[0]
	u, err = s.GetByID(ctx, first.UserID)
	if err != nil || first.Password == second.Password ||
		bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(first.Password)) == nil {
		t.Fatal("reissue did not replace the old password")
	}
	if err := s.SetPassword(ctx, u.ID, "weak"); err == nil {
		t.Fatal("weak password accepted")
	}
	assertPendingCount(t, s, 1)
	if err := s.SetPassword(ctx, u.ID, storeCredential("claimed")); err != nil {
		t.Fatal(err)
	}
	if len(*events) != 2 {
		t.Fatalf("expected issuance and retirement, got %d events", len(*events))
	}
	retired := (*events)[1]
	if retired.Kind != BootstrapRetired || retired.Generation != second.Generation ||
		retired.Reason != second.Reason || retired.UserID != u.ID || retired.Username != u.Username {
		t.Fatal("retirement metadata differs from pending issuance")
	}
	mustEnsure(t, s)
	if len(*events) != 2 {
		t.Fatal("claimed account was reissued")
	}
}

func testStrictRotateAccounts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	// Include default-password accounts both with and without the flag, a
	// non-default forced-change account without a pending row (old schema),
	// and an ordinary claimed account that must remain byte-for-byte unchanged.
	for _, tc := range []struct {
		name, password string
		mustChange     bool
	}{
		{"default-flag", "containd", true},
		{"default-no-flag", "containd", false},
		{"legacy-pending", storeCredential("pending"), true},
		{"untouched", storeCredential("claimed"), false},
	} {
		if _, err := insertUser(ctx, s.db, User{
			Username: tc.name, Role: "admin", MustChangePassword: tc.mustChange,
		}, tc.password, true); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.GetByUsername(ctx, "untouched")
	if err != nil {
		t.Fatal(err)
	}
	users, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(map[string]string)
	challenges := make(map[string]string)
	for _, u := range users {
		session, err := s.CreateSession(ctx, u.ID, time.Hour, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sessions[u.Username] = session.ID
		stored, err := s.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := s.CreateMFAChallenge(ctx, stored, MFAChallengeLogin, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		challenges[u.Username] = challenge
		if _, err := s.db.Exec(`INSERT INTO factor_failures (user_id,factor,failures) VALUES (?,'totp',3)`, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	var revoked []string
	cancel := s.SubscribeSessionRevocations(func(ids []string) {
		revoked = append(revoked, ids...)
		if _, err := s.List(ctx); err != nil {
			t.Fatal(err)
		}
	})
	defer cancel()
	events := bootstrapEvents(t, s)
	mustEnsure(t, s)
	if len(*events) != 3 || len(revoked) != 3 {
		t.Fatalf("issued=%d revoked=%d, want three each", len(*events), len(revoked))
	}
	for _, e := range *events {
		wantReason := "rotate"
		if e.Username == "legacy-pending" {
			wantReason = "reissue"
		}
		if e.Reason != wantReason || e.Generation != 1 {
			t.Fatal("incorrect migration reason/generation")
		}
		sess, err := s.GetSession(ctx, sessions[e.Username])
		if err != nil || !sess.Revoked {
			t.Fatalf("old session still valid: %v", err)
		}
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM mfa_challenges WHERE id=?`, challenges[e.Username]).Scan(&count); err != nil || count != 0 {
			t.Fatalf("challenge not invalidated: %v", err)
		}
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM factor_failures WHERE user_id=?`, e.UserID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("factor failures not cleared: %v", err)
		}
		u, err := s.GetByID(ctx, e.UserID)
		if err != nil || u.CredentialVersion != 1 {
			t.Fatalf("credential version not advanced: %v", err)
		}
	}
	after, err := s.GetByID(ctx, before.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("ordinary password account changed")
	}
	sess, err := s.GetSession(ctx, sessions["untouched"])
	if err != nil || sess.Revoked {
		t.Fatalf("ordinary account session revoked: %v", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mfa_challenges WHERE id=?`, challenges["untouched"]).Scan(&count); err != nil || count != 1 {
		t.Fatalf("ordinary challenge changed: %v", err)
	}
	mustEnsure(t, s)
	if len(*events) != 6 {
		t.Fatal("not every pending account was reissued")
	}
	for _, e := range (*events)[3:] {
		if e.Reason != "reissue" || e.Generation != 2 {
			t.Fatal("pending generation/reason not advanced")
		}
	}
}

func testStrictMissingNamedAdmin(t *testing.T) {
	s := newTestStore(t)
	events := bootstrapEvents(t, s)
	mustEnsure(t, s)
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", " named ")
	mustEnsure(t, s)
	if len(*events) != 3 || (*events)[1].Reason != "reissue" ||
		(*events)[2].Username != "named" || (*events)[2].Reason != "seed" {
		t.Fatalf("missing named admin was not seeded, events=%d", len(*events))
	}
	mustEnsure(t, s)
	if len(*events) != 5 {
		t.Fatal("existing named admin early return skipped pending accounts")
	}
}

func testStrictReset(t *testing.T) {
	s := newTestStore(t)
	events := bootstrapEvents(t, s)
	mustEnsure(t, s)
	old := (*events)[0]
	if err := s.ResetToDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*events) != 2 || (*events)[1].Reason != "reset" || (*events)[1].Generation != 1 ||
		(*events)[1].UserID == old.UserID {
		t.Fatal("reset did not publish a fresh committed account")
	}
	assertPendingCount(t, s, 1)
	if _, err := s.GetByID(context.Background(), old.UserID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old account survived reset: %v", err)
	}
}

func testStrictCommitFailure(t *testing.T) {
	for _, operation := range []string{"seed", "reissue", "rotate", "reset", "retire"} {
		t.Run(operation, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			if operation != "seed" {
				if operation == "rotate" {
					if _, err := insertUser(ctx, s.db, User{Username: "containd", Role: "admin"}, "containd", true); err != nil {
						t.Fatal(err)
					}
				} else {
					mustEnsure(t, s)
				}
				u, err := s.GetByUsername(ctx, "containd")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.CreateSession(ctx, u.ID, time.Hour, time.Hour); err != nil {
					t.Fatal(err)
				}
				if _, err := s.CreateMFAChallenge(ctx, u, MFAChallengeLogin, time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`INSERT INTO factor_failures (user_id,factor,failures) VALUES (?,'totp',3)`, u.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := bootstrapSnapshot(t, s)
			events := bootstrapEvents(t, s)
			var revoked []string
			cancel := s.SubscribeSessionRevocations(func(ids []string) { revoked = append(revoked, ids...) })
			defer cancel()
			triggerOp := "INSERT"
			if operation == "reissue" {
				triggerOp = "UPDATE"
			}
			if operation == "retire" {
				triggerOp = "DELETE"
			}
			// Deferred FK failure happens at COMMIT, after the issuance or
			// retirement statement has succeeded. No production test hook.
			if _, err := s.db.Exec(`CREATE TABLE commit_fault (
id TEXT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER fail_bootstrap_commit AFTER ` + triggerOp + ` ON bootstrap_pending
BEGIN INSERT INTO commit_fault VALUES ('missing-user'); END;`); err != nil {
				t.Fatal(err)
			}
			var err error
			switch operation {
			case "reset":
				err = s.ResetToDefaultAdmin(ctx)
			case "retire":
				u, getErr := s.GetByUsername(ctx, "containd")
				if getErr != nil {
					t.Fatal(getErr)
				}
				err = s.SetPassword(ctx, u.ID, storeCredential("claimed"))
			default:
				err = s.EnsureDefaultAdmin(ctx)
			}
			if err == nil || !strings.Contains(err.Error(), "commit ") {
				t.Fatalf("expected commit failure, got %v", err)
			}
			if len(*events) != 0 || len(revoked) != 0 {
				t.Fatal("failed commit published an event")
			}
			if after := bootstrapSnapshot(t, s); !reflect.DeepEqual(before, after) {
				t.Fatal("failed commit changed persistent state")
			}
			if _, err := s.db.Exec(`DROP TRIGGER fail_bootstrap_commit`); err != nil {
				t.Fatal(err)
			}
			mustEnsure(t, s)
			if len(*events) != 1 {
				t.Fatal("store could not recover after failed commit")
			}
		})
	}
}

func bootstrapSnapshot(t *testing.T, s *SQLiteStore) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT id || ':' || password_hash || ':' || must_change_password || ':' || credential_version FROM users
UNION ALL SELECT user_id || ':' || generation || ':' || reason || ':' || issued_at FROM bootstrap_pending
UNION ALL SELECT id || ':' || revoked FROM sessions
UNION ALL SELECT id || ':' || credential_version FROM mfa_challenges
UNION ALL SELECT user_id || ':' || factor || ':' || failures FROM factor_failures ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var snapshot []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		snapshot = append(snapshot, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestBootstrapPendingMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// A pre-MFA, pre-bootstrap database must gain the pending table without
	// changing the existing account's password.
	if _, err := db.Exec(`CREATE TABLE users (
id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, first_name TEXT, last_name TEXT, email TEXT,
role TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO users VALUES ('legacy','legacy','','','','admin','legacy-hash',1,1);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertPendingCount(t, s, 0)
	u, err := s.GetByID(context.Background(), "legacy")
	if err != nil || u.PasswordHash != "legacy-hash" || u.CredentialVersion != 0 {
		t.Fatalf("migration changed legacy account: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO bootstrap_pending VALUES ('legacy',1,'reissue',1);
DELETE FROM users WHERE id='legacy';`); err != nil {
		t.Fatal(err)
	}
	assertPendingCount(t, s, 0)
}

func TestBootstrapTrainingDefaults(t *testing.T) {
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
	for _, lab := range []string{"", "1"} {
		t.Run("lab="+lab, func(t *testing.T) {
			t.Setenv("CONTAIND_LAB_MODE", lab)
			s := newTestStore(t)
			events := bootstrapEvents(t, s)
			mustEnsure(t, s)
			u, err := s.GetByUsername(context.Background(), "containd")
			if err != nil || u.MustChangePassword != (lab == "") ||
				bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("containd")) != nil {
				t.Fatalf("training seed changed: %v", err)
			}
			t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "explicit")
			mustEnsure(t, s)
			named, err := s.GetByUsername(context.Background(), "explicit")
			if err != nil || named.MustChangePassword ||
				bcrypt.CompareHashAndPassword([]byte(named.PasswordHash), []byte("containd")) != nil {
				t.Fatalf("training explicit seed changed: %v", err)
			}
			mustEnsure(t, s)
			again, err := s.GetByID(context.Background(), u.ID)
			if err != nil || !reflect.DeepEqual(u, again) {
				t.Fatal("training boot reissued a password")
			}
			if err := s.ResetToDefaultAdmin(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertPendingCount(t, s, 0)
			if len(*events) != 0 {
				t.Fatal("training emitted bootstrap events")
			}
		})
	}
}
