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

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already exists")
	ErrLastAdmin     = errors.New("cannot delete last admin")
)

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role"` // admin|view
	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

type StoredUser struct {
	User
	PasswordHash string
}

type Store interface {
	List(ctx context.Context) ([]User, error)
	GetByUsername(ctx context.Context, username string) (*StoredUser, error)
	GetByID(ctx context.Context, id string) (*StoredUser, error)
	Create(ctx context.Context, u User, password string) (*User, error)
	Update(ctx context.Context, id string, patch User) (*User, error)
	Delete(ctx context.Context, id string) error
	SetPassword(ctx context.Context, id string, password string) error
	EnsureDefaultAdmin(ctx context.Context) error
	CreateSession(ctx context.Context, userID string, idleTTL time.Duration, maxTTL time.Duration) (*Session, error)
	GetSession(ctx context.Context, id string) (*Session, error)
	TouchSession(ctx context.Context, id string, idleTTL time.Duration, maxTTL time.Duration) (*Session, error)
	RevokeSession(ctx context.Context, id string) error
	Close() error
}

type SQLiteStore struct {
	db *sql.DB
}

// WipeAll deletes all users and sessions (factory reset). Caller may re-seed defaults.
func (s *SQLiteStore) WipeAll(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("users store unavailable")
	}
	// Clear sessions first to avoid FK complaints in some SQLite configurations.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return fmt.Errorf("wipe sessions: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users`); err != nil {
		return fmt.Errorf("wipe users: %w", err)
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
);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create users schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) EnsureDefaultAdmin(ctx context.Context) error {
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
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		if strings.TrimSpace(os.Getenv("CONTAIND_DEFAULT_ADMIN_USERNAME")) == "" {
			return nil
		}
		// If the user already exists, do nothing.
		if _, err := s.GetByUsername(ctx, username); err == nil {
			return nil
		}
		// Otherwise create it (explicit operator intent).
		_, err := s.Create(ctx, User{
			Username:  username,
			FirstName: "Default",
			LastName:  "Admin",
			Role:      "admin",
			Email:     "",
		}, password)
		return err
	}

	// Fresh DB: always seed the default admin.
	_, err := s.Create(ctx, User{
		Username:  username,
		FirstName: "Default",
		LastName:  "Admin",
		Role:      "admin",
		Email:     "",
	}, password)
	return err
}

func (s *SQLiteStore) List(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, first_name, last_name, email, role, created_at, updated_at FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var cAt, uAt int64
		if err := rows.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email, &u.Role, &cAt, &uAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
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
	row := s.db.QueryRowContext(ctx, `SELECT id, username, first_name, last_name, email, role, password_hash, created_at, updated_at FROM users WHERE username = ?`, username)
	var u StoredUser
	var cAt, uAt int64
	if err := row.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.PasswordHash, &cAt, &uAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.CreatedAt = time.Unix(cAt, 0).UTC()
	u.UpdatedAt = time.Unix(uAt, 0).UTC()
	return &u, nil
}

func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*StoredUser, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, username, first_name, last_name, email, role, password_hash, created_at, updated_at FROM users WHERE id = ?`, id)
	var u StoredUser
	var cAt, uAt int64
	if err := row.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.PasswordHash, &cAt, &uAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	u.CreatedAt = time.Unix(cAt, 0).UTC()
	u.UpdatedAt = time.Unix(uAt, 0).UTC()
	return &u, nil
}

func (s *SQLiteStore) Create(ctx context.Context, u User, password string) (*User, error) {
	if strings.TrimSpace(u.Username) == "" {
		return nil, errors.New("username required")
	}
	if u.Role != "admin" && u.Role != "view" {
		return nil, fmt.Errorf("invalid role %q", u.Role)
	}
	if password == "" {
		return nil, errors.New("password required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	u.ID = newID()
	u.CreatedAt = now
	u.UpdatedAt = now
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, first_name, last_name, email, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.FirstName, u.LastName, u.Email, u.Role, string(hash), now.Unix(), now.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return &u, nil
}

func (s *SQLiteStore) Update(ctx context.Context, id string, patch User) (*User, error) {
	existing, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	u := existing.User
	if patch.FirstName != "" || patch.FirstName == "" {
		u.FirstName = patch.FirstName
	}
	if patch.LastName != "" || patch.LastName == "" {
		u.LastName = patch.LastName
	}
	if patch.Email != "" || patch.Email == "" {
		u.Email = patch.Email
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
	return nil
}

func (s *SQLiteStore) SetPassword(ctx context.Context, id string, password string) error {
	if password == "" {
		return errors.New("password required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, string(hash), now.Unix(), id)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
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
