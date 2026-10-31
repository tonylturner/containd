// SPDX-License-Identifier: Apache-2.0
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	MFAChallengeLogin  = "mfa_login"
	MFAChallengeEnroll = "mfa_enroll"
)

var ErrMFAChallenge = errors.New("invalid, used or expired MFA challenge; start again")

// CreateMFAChallenge binds a nonce to the credential state actually authenticated
// by the caller, not a later password/role/TOTP state read after authentication.
func (s *SQLiteStore) CreateMFAChallenge(ctx context.Context, u *StoredUser, purpose string, expires time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE expires_at<=?`, time.Now().Unix()); err != nil {
		return "", err
	}
	id := newID()
	res, err := tx.ExecContext(ctx, `INSERT INTO mfa_challenges (id,user_id,purpose,credential_version,expires_at)
 SELECT ?,id,?,credential_version,? FROM users WHERE id=? AND credential_version=? AND password_hash=? AND role=? AND mfa_totp_secret=? AND mfa_totp_enabled=?`, id, purpose, expires.Unix(), u.ID, u.CredentialVersion, u.PasswordHash, u.Role, u.TOTPSecret, u.MFAEnabled)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrMFAChallenge
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

// invalidateChallenges runs in the credential/role mutation's transaction.
func invalidateChallenges(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET credential_version=credential_version+1 WHERE id=?`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE user_id=?`, id)
	return err
}

// challengeTx reserves the writer before checking the durable nonce, preventing
// a concurrent redemption or credential mutation from interleaving with it.
func (s *SQLiteStore) challengeTx(ctx context.Context, id, userID, purpose string, now time.Time) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE expires_at<=?`, now.Unix()); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	var found int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM mfa_challenges c JOIN users u ON u.id=c.user_id WHERE c.id=? AND c.user_id=? AND c.purpose=? AND c.credential_version=u.credential_version`, id, userID, purpose).Scan(&found)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return nil, ErrMFAChallenge
		}
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

// RedeemLoginMFA atomically checks the factor and consumes the challenge on
// success. A failed code leaves it usable, but persists per-account throttling.
func (s *SQLiteStore) RedeemLoginMFA(ctx context.Context, id, userID, code string, now time.Time) error {
	tx, err := s.challengeTx(ctx, id, userID, MFAChallengeLogin, now)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result := acceptTOTP(ctx, tx, userID, code, now)
	if result != nil {
		if _, _, refused := Refusal(result); !refused {
			return result
		}
	} else if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE id=?`, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit MFA login: %w", err)
	}
	return result
}

// RedeemEnrollMFA consumes the enrollment challenge and installs the secret in
// one transaction, retaining the acting session exactly as SetTOTP does.
func (s *SQLiteStore) RedeemEnrollMFA(ctx context.Context, id, userID, secret, code string, now time.Time) error {
	tx, err := s.challengeTx(ctx, id, userID, MFAChallengeEnroll, now)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	u, err := getByID(ctx, tx, userID)
	if err != nil {
		return err
	}
	if u.MFAEnabled {
		return ErrMFAChallenge
	}
	if !ValidateTOTP(secret, code, now) {
		return ErrInvalidTOTP
	}
	revoked, err := updateCredentialTx(ctx, tx, "enable totp", userID, FactorTOTP, `UPDATE users SET mfa_totp_secret=?, mfa_totp_enabled=1, mfa_totp_last_step=0, mfa_grace_until=0, updated_at=? WHERE id=?`, secret, now.Unix(), userID)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.revocations.publish(revoked)
	return nil
}
