// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteStoreMigrationAlterFailure(t *testing.T) {
	for _, column := range []string{
		"must_change_password", "mfa_totp_secret", "mfa_totp_enabled",
		"mfa_required", "mfa_grace_until", "mfa_totp_last_step", "credential_version",
	} {
		t.Run(column, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.db")
			s, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatal(err)
			}
			// Keep every other table/column current so opening read-only fails
			// specifically at this ALTER, not schema creation or WAL setup.
			if _, err := s.db.Exec("ALTER TABLE users DROP COLUMN " + column); err != nil {
				s.Close()
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := NewSQLiteStore("file:" + path + "?mode=ro")
			if opened != nil {
				opened.Close()
				t.Fatal("Open returned a store despite a required read-only ALTER")
			}
			if err == nil || !strings.Contains(err.Error(), "migrate users column "+column) ||
				!strings.Contains(strings.ToLower(err.Error()), "readonly") {
				t.Fatalf("Open must report this ALTER's read-only failure, got %v", err)
			}
			// The failed open must close its connection and allow a normal retry.
			retried, err := NewSQLiteStore(path)
			if err != nil {
				t.Fatalf("writable retry: %v", err)
			}
			if err := retried.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteStoreMigrationReopenPreMFA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (
id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, first_name TEXT, last_name TEXT, email TEXT,
role TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT INTO users VALUES ('legacy','legacy','','','','admin','legacy-hash',1,1);`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for boot := range 2 {
		s, err := NewSQLiteStore(path)
		if err != nil {
			t.Fatalf("boot %d: %v", boot, err)
		}
		t.Cleanup(func() { s.Close() })
		u, err := s.GetByID(context.Background(), "legacy")
		if err != nil || u.PasswordHash != "legacy-hash" || u.Role != "admin" {
			t.Fatalf("boot %d changed legacy account: %+v, %v", boot, u, err)
		}
		var mustChange, enabled, required, grace, lastStep, version int
		var secret string
		if err := s.db.QueryRow(`SELECT must_change_password, mfa_totp_secret, mfa_totp_enabled,
mfa_required, mfa_grace_until, mfa_totp_last_step, credential_version FROM users WHERE id='legacy'`).
			Scan(&mustChange, &secret, &enabled, &required, &grace, &lastStep, &version); err != nil {
			t.Fatal(err)
		}
		if boot == 0 {
			if mustChange != 0 || secret != "" || enabled != 0 || required != 0 ||
				grace != 0 || lastStep != 0 || version != 0 {
				t.Fatal("pre-MFA migration did not preserve zero-value defaults")
			}
			if _, err := s.db.Exec(`UPDATE users SET must_change_password=1, mfa_totp_secret='saved-secret',
mfa_totp_enabled=1, mfa_required=1, mfa_grace_until=123, mfa_totp_last_step=456, credential_version=7`); err != nil {
				t.Fatal(err)
			}
		} else if mustChange != 1 || secret != "saved-secret" || enabled != 1 || required != 1 ||
			grace != 123 || lastStep != 456 || version != 7 {
			t.Fatal("reopening an already migrated database changed stored values")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
