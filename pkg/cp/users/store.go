// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package users

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/common/labmode"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already exists")
	ErrLastAdmin     = errors.New("cannot delete last admin")
)

type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	FirstName          string     `json:"firstName,omitempty"`
	LastName           string     `json:"lastName,omitempty"`
	Email              string     `json:"email,omitempty"`
	Role               string     `json:"role"` // admin|view
	MustChangePassword bool       `json:"mustChangePassword,omitempty"`
	MFAEnabled         bool       `json:"mfaEnabled,omitempty"`
	MFARequired        bool       `json:"mfaRequired,omitempty"`
	MFAGraceUntil      *time.Time `json:"mfaGraceUntil,omitempty"`
	CreatedAt          time.Time  `json:"createdAt,omitempty"`
	UpdatedAt          time.Time  `json:"updatedAt,omitempty"`
}

// Patch distinguishes omitted profile fields from an explicit empty string.
type Patch struct {
	FirstName *string `json:"firstName,omitempty"`
	LastName  *string `json:"lastName,omitempty"`
	Email     *string `json:"email,omitempty"`
	Role      string  `json:"role,omitempty"`
}

type StoredUser struct {
	User
	PasswordHash string
	TOTPSecret   string
}

type Store interface {
	List(ctx context.Context) ([]User, error)
	GetByUsername(ctx context.Context, username string) (*StoredUser, error)
	GetByID(ctx context.Context, id string) (*StoredUser, error)
	Create(ctx context.Context, u User, password string) (*User, error)
	Update(ctx context.Context, id string, patch Patch) (*User, error)
	Delete(ctx context.Context, id string) error
	SetPassword(ctx context.Context, id string, password string) error
	SetTOTP(ctx context.Context, id string, secret string) error
	DisableTOTP(ctx context.Context, id string) error
	AcceptTOTP(ctx context.Context, id string, code string, now time.Time) error
	CheckCurrentPassword(ctx context.Context, id string, password string, now time.Time) error
	SetMFARequirement(ctx context.Context, id string, required bool, graceUntil *time.Time) error
	EnsureDefaultAdmin(ctx context.Context) error
	CreateSession(ctx context.Context, userID string, idleTTL time.Duration, maxTTL time.Duration) (*Session, error)
	GetSession(ctx context.Context, id string) (*Session, error)
	TouchSession(ctx context.Context, id string, idleTTL time.Duration, maxTTL time.Duration) (*Session, error)
	RevokeSession(ctx context.Context, id string) error
	SubscribeSessionRevocations(fn func(sessionIDs []string)) func()
	Close() error
}

// SQLiteStore keeps accounts and sessions. SetPassword, SetTOTP and
// DisableTOTP revoke the account's other sessions in the same transaction.
type SQLiteStore struct {
	db          *sql.DB
	revocations revocationHub
}

// ResetToDefaultAdmin replaces users and sessions with the default admin atomically.
func (s *SQLiteStore) ResetToDefaultAdmin(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("users store unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Clear sessions first to avoid FK complaints in some SQLite configurations.
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return fmt.Errorf("wipe sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users`); err != nil {
		return fmt.Errorf("wipe users: %w", err)
	}
	if err := ensureDefaultAdmin(ctx, tx); err != nil {
		return fmt.Errorf("seed default admin: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user reset: %w", err)
	}
	return nil
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open users sqlite: %w", err)
	}
	// This store is hit on every authenticated API request (session sliding window),
	// so keep SQLite access serialized to avoid SQLITE_BUSY races under concurrent HTTP calls.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := tuneSQLite(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := bootstrap(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func tuneSQLite(db *sql.DB) error {
	// Pragmas are applied per-connection. With SetMaxOpenConns(1), this reliably applies
	// to all operations in this store.
	pragmas := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA foreign_keys=ON;`,
		`PRAGMA busy_timeout=5000;`,
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("sqlite pragma %q: %w", p, err)
		}
	}
	return nil
}

func bootstrap(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  first_name TEXT,
  last_name TEXT,
  email TEXT,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  mfa_totp_secret TEXT NOT NULL DEFAULT '',
  mfa_totp_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_required INTEGER NOT NULL DEFAULT 0,
  mfa_grace_until INTEGER NOT NULL DEFAULT 0,
  mfa_totp_last_step INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS factor_failures (
  user_id TEXT NOT NULL,
  factor TEXT NOT NULL,
  failures INTEGER NOT NULL DEFAULT 0,
  last_failure INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  lock_reported INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id, factor),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create users schema: %w", err)
	}
	// Migrate existing databases: add must_change_password column if missing.
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN mfa_totp_secret TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN mfa_totp_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN mfa_grace_until INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN mfa_totp_last_step INTEGER NOT NULL DEFAULT 0`)
	return nil
}

func (s *SQLiteStore) EnsureDefaultAdmin(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("users store unavailable")
	}
	return ensureDefaultAdmin(ctx, s.db)
}

type userDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type userQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func ensureDefaultAdmin(ctx context.Context, db userDB) error {
	username := strings.TrimSpace(os.Getenv("CONTAIND_DEFAULT_ADMIN_USERNAME"))
	password := os.Getenv("CONTAIND_DEFAULT_ADMIN_PASSWORD")
	if username == "" {
		username = "containd"
	}
	if password == "" {
		password = "containd"
	}

	// If there are already users, do not silently create additional admins unless the operator
	// explicitly set CONTAIND_DEFAULT_ADMIN_USERNAME/PASSWORD and that user doesn't exist yet.
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		if strings.TrimSpace(os.Getenv("CONTAIND_DEFAULT_ADMIN_USERNAME")) == "" {
			return nil
		}
		// If the user already exists, do nothing.
		var existingID string
		err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, username).Scan(&existingID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check default admin: %w", err)
		}
		// Otherwise create it (explicit operator intent).
		_, err = insertUser(ctx, db, User{
			Username:  username,
			FirstName: "Default",
			LastName:  "Admin",
			Role:      "admin",
			Email:     "",
		}, password, true)
		return err
	}

	// Fresh DB: seed the default admin. The must-change-password flag is
	// raised when the seeded password is the well-known default
	// `containd`, except in lab mode where the canonical credential is
	// pinned by design (workshop docs, lab YAMLs, and SSH-on-:2222 all
	// expect `containd/containd`). SetPassword refuses every change in
	// lab mode, so the flag could never be cleared there; leaving it
	// unset keeps the API responses consistent with the enforcement.
	_, err := insertUser(ctx, db, User{
		Username:           username,
		FirstName:          "Default",
		LastName:           "Admin",
		Role:               "admin",
		Email:              "",
		MustChangePassword: password == "containd" && !labmode.Enabled(),
	}, password, true)
	return err
}

func graceUntilPtr(unix int64) *time.Time {
	if unix <= 0 {
		return nil
	}
	t := time.Unix(unix, 0).UTC()
	return &t
}

func (s *SQLiteStore) List(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, first_name, last_name, email, role, must_change_password, mfa_totp_enabled, mfa_required, mfa_grace_until, created_at, updated_at FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var cAt, uAt, graceUntil int64
		if err := rows.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.MustChangePassword, &u.MFAEnabled, &u.MFARequired, &graceUntil, &cAt, &uAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.MFAGraceUntil = graceUntilPtr(graceUntil)
		u.CreatedAt = time.Unix(cAt, 0).UTC()
		u.UpdatedAt = time.Unix(uAt, 0).UTC()
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return out, nil
}

func (s *SQLiteStore) GetByUsername(ctx context.Context, username string) (*StoredUser, error) {
	username = strings.TrimSpace(username)
	row := s.db.QueryRowContext(ctx, `SELECT id, username, first_name, last_name, email, role, password_hash, must_change_password, mfa_totp_secret, mfa_totp_enabled, mfa_required, mfa_grace_until, created_at, updated_at FROM users WHERE username = ?`, username)
	var u StoredUser
	var cAt, uAt, graceUntil int64
	if err := row.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.PasswordHash, &u.MustChangePassword, &u.TOTPSecret, &u.MFAEnabled, &u.MFARequired, &graceUntil, &cAt, &uAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.MFAGraceUntil = graceUntilPtr(graceUntil)
	u.CreatedAt = time.Unix(cAt, 0).UTC()
	u.UpdatedAt = time.Unix(uAt, 0).UTC()
	return &u, nil
}

func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*StoredUser, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, first_name, last_name, email, role, password_hash, must_change_password, mfa_totp_secret, mfa_totp_enabled, mfa_required, mfa_grace_until, created_at, updated_at FROM users WHERE id = ?`, id)
	var u StoredUser
	var cAt, uAt, graceUntil int64
	if err := row.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.PasswordHash, &u.MustChangePassword, &u.TOTPSecret, &u.MFAEnabled, &u.MFARequired, &graceUntil, &cAt, &uAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.MFAGraceUntil = graceUntilPtr(graceUntil)
	u.CreatedAt = time.Unix(cAt, 0).UTC()
	u.UpdatedAt = time.Unix(uAt, 0).UTC()
	return &u, nil
}

// PasswordPolicyError reports a new password that the password rules refuse.
type PasswordPolicyError struct{ reason string }

func (e *PasswordPolicyError) Error() string { return e.reason }

// IsPasswordPolicyError reports whether err refuses a password on policy
// grounds (rules or reuse) rather than a store failure.
func IsPasswordPolicyError(err error) bool {
	var policy *PasswordPolicyError
	return errors.As(err, &policy)
}

// ErrPasswordReuse refuses a new password that matches the current one.
var ErrPasswordReuse error = &PasswordPolicyError{reason: "new password must differ from the current password"}

func validatePassword(pw string) error {
	if pw == "" {
		return &PasswordPolicyError{reason: "password required"}
	}
	if len(pw) < 8 {
		return &PasswordPolicyError{reason: "password must be at least 8 characters"}
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return &PasswordPolicyError{reason: "password must contain uppercase, lowercase, and a digit"}
	}
	return nil
}

func (s *SQLiteStore) Create(ctx context.Context, u User, password string) (*User, error) {
	return s.createUser(ctx, u, password, false)
}

func (s *SQLiteStore) createUser(ctx context.Context, u User, password string, bootstrap bool) (*User, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("users store unavailable")
	}
	return insertUser(ctx, s.db, u, password, bootstrap)
}

func insertUser(ctx context.Context, db userDB, u User, password string, bootstrap bool) (*User, error) {
	if strings.TrimSpace(u.Username) == "" {
		return nil, errors.New("username required")
	}
	if u.Role != "admin" && u.Role != "view" {
		return nil, fmt.Errorf("invalid role %q", u.Role)
	}
	if bootstrap {
		if password == "" {
			return nil, errors.New("password required")
		}
	} else if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	u.ID = newID()
	u.CreatedAt = now
	u.UpdatedAt = now
	mustChange := 0
	if u.MustChangePassword {
		mustChange = 1
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO users (id, username, first_name, last_name, email, role, password_hash, must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.FirstName, u.LastName, u.Email, u.Role, string(hash), mustChange, now.Unix(), now.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return &u, nil
}

func (s *SQLiteStore) Update(ctx context.Context, id string, patch Patch) (*User, error) {
	existing, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	u := existing.User
	if patch.FirstName != nil {
		u.FirstName = *patch.FirstName
	}
	if patch.LastName != nil {
		u.LastName = *patch.LastName
	}
	if patch.Email != nil {
		u.Email = *patch.Email
	}
	if patch.Role != "" {
		if patch.Role != "admin" && patch.Role != "view" {
			return nil, fmt.Errorf("invalid role %q", patch.Role)
		}
		u.Role = patch.Role
	}
	u.UpdatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET first_name=?, last_name=?, email=?, role=?, updated_at=? WHERE id=?`,
		u.FirstName, u.LastName, u.Email, u.Role, u.UpdatedAt.Unix(), id)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return &u, nil
}

func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	existing, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if existing.Role == "admin" {
		var adminCount int
		row := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE role = 'admin'`)
		if err := row.Scan(&adminCount); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if adminCount <= 1 {
			return ErrLastAdmin
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete: %w", err)
	}
	removed, err := activeSessionIDs(ctx, tx, id, "")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete sessions: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete: %w", err)
	}
	s.revocations.publish(removed)
	return nil
}

// SetPassword replaces a user's password, revokes the account's other
// sessions and clears its TOTP and current-password failure counts. It is the
// single entry point for password changes: it returns ErrPasswordChangeLabMode
// in lab mode and ErrPasswordReuse when the new password matches the current
// one.
func (s *SQLiteStore) SetPassword(ctx context.Context, id string, password string) error {
	if err := CheckPasswordChange(); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	current, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(current.PasswordHash), []byte(password)) == nil {
		return ErrPasswordReuse
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	return s.updateCredential(ctx, "set password", id, "", `UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?`, string(hash), now.Unix(), id)
}

// SetTOTP enables TOTP with secret and revokes the account's other sessions.
// The new secret starts with no accepted time step and no failed codes.
func (s *SQLiteStore) SetTOTP(ctx context.Context, id string, secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return errors.New("totp secret required")
	}
	now := time.Now().UTC()
	return s.updateCredential(ctx, "set totp", id, FactorTOTP, `UPDATE users SET mfa_totp_secret=?, mfa_totp_enabled=1, mfa_totp_last_step=0, mfa_grace_until=0, updated_at=? WHERE id=?`, secret, now.Unix(), id)
}

// DisableTOTP removes TOTP, its failure count and the account's other
// sessions.
func (s *SQLiteStore) DisableTOTP(ctx context.Context, id string) error {
	now := time.Now().UTC()
	return s.updateCredential(ctx, "disable totp", id, FactorTOTP, `UPDATE users SET mfa_totp_secret='', mfa_totp_enabled=0, mfa_totp_last_step=0, mfa_grace_until=0, updated_at=? WHERE id=?`, now.Unix(), id)
}

// updateCredential applies one credential update, clears the failure count
// of factor (every factor when empty) and revokes the account's other
// sessions atomically, then notifies revocation subscribers.
func (s *SQLiteStore) updateCredential(ctx context.Context, op, id string, factor Factor, query string, args ...any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s: %w", op, err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if factor == "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM factor_failures WHERE user_id = ?`, id)
	} else {
		err = clearFactor(ctx, tx, id, factor)
	}
	if err != nil {
		return fmt.Errorf("%s: clear failures: %w", op, err)
	}
	revoked, err := revokeOtherSessions(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", op, err)
	}
	s.revocations.publish(revoked)
	return nil
}

func (s *SQLiteStore) SetMFARequirement(ctx context.Context, id string, required bool, graceUntil *time.Time) error {
	now := time.Now().UTC()
	requiredInt := 0
	graceUnix := int64(0)
	if required {
		requiredInt = 1
		if graceUntil != nil {
			graceUnix = graceUntil.UTC().Unix()
		}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET mfa_required=?, mfa_grace_until=?, updated_at=? WHERE id=?`, requiredInt, graceUnix, now.Unix(), id)
	if err != nil {
		return fmt.Errorf("set mfa requirement: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	IssuedAt  time.Time `json:"issuedAt"`
	LastSeen  time.Time `json:"lastSeen"`
	ExpiresAt time.Time `json:"expiresAt"`
	Revoked   bool      `json:"revoked"`
}

func (s *SQLiteStore) CreateSession(ctx context.Context, userID string, idleTTL time.Duration, maxTTL time.Duration) (*Session, error) {
	now := time.Now().UTC()
	id := newID()
	exp := now.Add(idleTTL)
	maxExp := now.Add(maxTTL)
	if exp.After(maxExp) {
		exp = maxExp
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, issued_at, last_seen, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 0)`,
		id, userID, now.UnixNano(), now.UnixNano(), exp.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &Session{ID: id, UserID: userID, IssuedAt: now, LastSeen: now, ExpiresAt: exp}, nil
}

func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, user_id, issued_at, last_seen, expires_at, revoked FROM sessions WHERE id = ?`, id)
	var sess Session
	var issued, seen, exp int64
	var revoked int
	if err := row.Scan(&sess.ID, &sess.UserID, &issued, &seen, &exp, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	sess.IssuedAt = time.Unix(0, issued).UTC()
	sess.LastSeen = time.Unix(0, seen).UTC()
	sess.ExpiresAt = time.Unix(0, exp).UTC()
	sess.Revoked = revoked != 0
	return &sess, nil
}

func (s *SQLiteStore) TouchSession(ctx context.Context, id string, idleTTL time.Duration, maxTTL time.Duration) (*Session, error) {
	sess, err := s.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if sess.Revoked {
		return nil, errors.New("session revoked")
	}
	now := time.Now().UTC()
	maxExp := sess.IssuedAt.Add(maxTTL)
	newExp := now.Add(idleTTL)
	if newExp.After(maxExp) {
		newExp = maxExp
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen=?, expires_at=? WHERE id=?`,
		now.UnixNano(), newExp.UnixNano(), id)
	if err != nil {
		return nil, fmt.Errorf("touch session: %w", err)
	}
	sess.LastSeen = now
	sess.ExpiresAt = newExp
	return sess, nil
}

func (s *SQLiteStore) RevokeSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
