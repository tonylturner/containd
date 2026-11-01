// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestAdminMFADisableTransactionFailure(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "0")
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "users.db")
	store, err := users.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	u, err := store.Create(ctx, users.User{Username: "mfa-user", Role: "view"}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTOTP(ctx, u.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMFARequirement(ctx, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	session, err := store.CreateSession(ctx, u.ID, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER reject_mfa_disable
BEFORE UPDATE OF revoked ON sessions
WHEN (SELECT mfa_totp_enabled=0 AND mfa_grace_until>0 FROM users WHERE id=OLD.user_id)
BEGIN SELECT RAISE(ABORT, 'injected disable failure'); END`); err != nil {
		t.Fatal(err)
	}
	audits := &mockAuditStore{}
	router := gin.New()
	router.Use(withAuditStore(audits))
	router.POST("/users/:id/mfa/disable", disableUserMFAHandler(store))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users/"+u.ID+"/mfa/disable", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "injected disable failure") {
		t.Fatalf("disable = %d %s", rec.Code, rec.Body.String())
	}
	after, err := store.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed disable changed user: before=%+v after=%+v", before, after)
	}
	gotSession, err := store.GetSession(ctx, session.ID)
	if err != nil || gotSession.Revoked {
		t.Fatalf("failed disable changed session: %+v %v", gotSession, err)
	}
	if len(audits.records) != 0 {
		t.Fatalf("failed disable audited: %+v", audits.records)
	}
	// A retry after the fault is removed commits and audits exactly once.
	if _, err := db.ExecContext(ctx, `DROP TRIGGER reject_mfa_disable`); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users/"+u.ID+"/mfa/disable", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body.String())
	}
	if len(audits.records) != 1 || audits.records[0].Action != "auth.mfa.disable_admin" || audits.records[0].Result != "success" {
		t.Fatalf("success audit = %+v", audits.records)
	}
}
