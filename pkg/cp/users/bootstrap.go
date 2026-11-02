// SPDX-License-Identifier: Apache-2.0

package users

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/profile"
	"golang.org/x/crypto/bcrypt"
)

// A failed SQLite COMMIT can leave a transaction open in the driver after
// database/sql has marked its Tx done. Keep its connection reserved so it can
// be rolled back on failure rather than returning uncommitted credentials to
// the pool.
type bootstrapTx struct {
	*sql.Tx
	conn *sql.Conn
}

func (s *SQLiteStore) beginBootstrapTx(ctx context.Context) (*bootstrapTx, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &bootstrapTx{Tx: tx, conn: conn}, nil
}

func (tx *bootstrapTx) close() {
	_ = tx.Rollback()
	_ = tx.conn.Close()
}

func (tx *bootstrapTx) commit(ctx context.Context) error {
	err := tx.Commit()
	if err != nil {
		if _, rollbackErr := tx.conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`); rollbackErr != nil {
			// Never reuse a connection whose transaction state is unknown.
			_ = tx.conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}
	return err
}

// seedDefaultAdminTx collects private delivery events without publishing them.
// The caller owns the transaction and must publish only after successful commit.
func seedDefaultAdminTx(ctx context.Context, tx *sql.Tx, seedReason string) ([]BootstrapEvent, []string, error) {
	if !profile.IsStrict() {
		return nil, nil, ensureDefaultAdmin(ctx, tx)
	}

	// Read every account before deciding whether an explicitly named admin is
	// needed. Existing accounts must not escape rotation through an early return.
	rows, err := tx.QueryContext(ctx, `SELECT id, username, password_hash, must_change_password FROM users ORDER BY username`)
	if err != nil {
		return nil, nil, fmt.Errorf("list bootstrap accounts: %w", err)
	}
	var accounts []StoredUser
	for rows.Next() {
		var u StoredUser
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan bootstrap account: %w", err)
		}
		accounts = append(accounts, u)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("iterate bootstrap accounts: %w", err)
	}

	username := strings.TrimSpace(os.Getenv("CONTAIND_DEFAULT_ADMIN_USERNAME"))
	explicit := username != ""
	if username == "" {
		username = "containd"
	}
	found := false
	var events []BootstrapEvent
	var revoked []string
	for _, u := range accounts {
		found = found || u.Username == username
		reason := ""
		switch {
		case bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("containd")) == nil:
			reason = "rotate"
		case u.MustChangePassword:
			reason = "reissue"
		}
		if reason == "" {
			continue
		}
		event, ids, err := issueBootstrapTx(ctx, tx, u.User, reason, false)
		if err != nil {
			return nil, nil, err
		}
		events = append(events, event)
		revoked = append(revoked, ids...)
	}
	if len(accounts) == 0 || (explicit && !found) {
		event, ids, err := issueBootstrapTx(ctx, tx, User{
			Username: username, FirstName: "Default", LastName: "Admin", Role: "admin",
		}, seedReason, true)
		if err != nil {
			return nil, nil, err
		}
		events = append(events, event)
		revoked = append(revoked, ids...)
	}
	return events, revoked, nil
}

func issueBootstrapTx(ctx context.Context, tx *sql.Tx, u User, reason string, create bool) (BootstrapEvent, []string, error) {
	// 256 random bits, printable without whitespace, and guaranteed to satisfy
	// the ordinary password policy. Only the bcrypt hash is persisted.
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return BootstrapEvent{}, nil, fmt.Errorf("generate bootstrap password: %w", err)
	}
	password := "Aa1-" + base64.RawURLEncoding.EncodeToString(random[:])
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return BootstrapEvent{}, nil, fmt.Errorf("hash bootstrap password: %w", err)
	}
	if create {
		inserted, err := insertHashedUser(ctx, tx, u, string(hash))
		if err != nil {
			return BootstrapEvent{}, nil, err
		}
		u = *inserted
	}
	now := time.Now().Unix()
	revoked, err := updateCredentialTx(ctx, tx, "issue bootstrap password", u.ID, "",
		`UPDATE users SET password_hash=?, must_change_password=1, updated_at=? WHERE id=?`, string(hash), now, u.ID)
	if err != nil {
		return BootstrapEvent{}, nil, err
	}
	var generation int64
	err = tx.QueryRowContext(ctx, `INSERT INTO bootstrap_pending (user_id, generation, reason, issued_at)
VALUES (?, 1, ?, ?) ON CONFLICT(user_id) DO UPDATE SET
generation=bootstrap_pending.generation+1, reason=excluded.reason, issued_at=excluded.issued_at
RETURNING generation`, u.ID, reason, now).Scan(&generation)
	if err != nil {
		return BootstrapEvent{}, nil, fmt.Errorf("record bootstrap issuance: %w", err)
	}
	return BootstrapEvent{
		Kind: BootstrapIssued, Username: u.Username, UserID: u.ID,
		Generation: generation, Reason: reason, Password: password,
	}, revoked, nil
}

// setPasswordHash retires any outstanding issuance together with the credential
// change, including when an operator changes back to the training profile.
func (s *SQLiteStore) setPasswordHash(ctx context.Context, id, hash string) error {
	tx, err := s.beginBootstrapTx(ctx)
	if err != nil {
		return fmt.Errorf("begin set password: %w", err)
	}
	defer tx.close()
	var event BootstrapEvent
	err = tx.QueryRowContext(ctx, `SELECT u.username, p.generation, p.reason FROM bootstrap_pending p
JOIN users u ON u.id=p.user_id WHERE p.user_id=?`, id).Scan(&event.Username, &event.Generation, &event.Reason)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read bootstrap retirement: %w", err)
	}
	pending := err == nil
	revoked, err := updateCredentialTx(ctx, tx.Tx, "set password", id, "",
		`UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?`, hash, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM bootstrap_pending WHERE user_id=?`, id); err != nil {
		return fmt.Errorf("retire bootstrap password: %w", err)
	}
	if err := tx.commit(ctx); err != nil {
		return fmt.Errorf("commit set password: %w", err)
	}
	tx.close()
	s.revocations.publish(revoked)
	if pending {
		event.Kind = BootstrapRetired
		event.UserID = id
		s.emitBootstrapEvents([]BootstrapEvent{event})
	}
	return nil
}
