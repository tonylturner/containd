// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestFactoryResetApplyFailurePreservesStores(t *testing.T) {
	for _, mode := range []string{"nft", "reapply", "dataplane"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			store := stageStore(t)
			running, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			running.System.Hostname = "pre-reset"
			running.DataPlane.Enforcement = true
			running.Firewall.DefaultAction = config.ActionAllow
			if err := testSaveCandidate(store, ctx, running); err != nil {
				t.Fatal(err)
			}
			if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
				t.Fatal(err)
			}
			running, err = store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			candidate := config.DefaultConfig()
			candidate.System.Hostname = "staged-before-reset"
			candidate.IDS.Rules = []config.IDSRule{}
			if err := testSaveCandidate(store, ctx, candidate); err != nil {
				t.Fatal(err)
			}
			candidate, err = store.LoadCandidate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { userStore.Close() })
			user, err := userStore.Create(ctx, users.User{Username: "operator", Role: "admin"}, "StrongPassword123")
			if err != nil {
				t.Fatal(err)
			}
			if err := userStore.SetTOTP(ctx, user.ID, "JBSWY3DPEHPK3PXP"); err != nil {
				t.Fatal(err)
			}
			beforeUser, err := userStore.GetByID(ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := userStore.CreateSession(ctx, user.ID, time.Hour, 2*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			auditStore, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { auditStore.Close() })
			if err := auditStore.Add(ctx, audit.Record{Action: "pre.reset", Result: "success"}); err != nil {
				t.Fatal(err)
			}
			engine := &transactionalEngine{mockEngine: &mockEngine{}, failRestore: mode == "reapply"}
			if mode == "dataplane" {
				engine.configureErr = errors.New("dataplane unavailable")
			}
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(ctxSessionKey, sess.ID)
				c.Set("auditStore", auditStore)
				c.Next()
			})
			revoked := false
			router.GET("/api/v1/config/candidate", getCandidateConfigHandler(store))
			router.POST("/system/factory-reset", factoryResetHandler(store, userStore, engine, nil, func(context.Context, string) { revoked = true }))
			rec := httptest.NewRecorder()
			serveWithConfigRevision(t, router, rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, "/system/factory-reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`))))
			var body struct {
				Error        string `json:"error"`
				Detail       string `json:"detail"`
				Restored     bool   `json:"restored"`
				Reapplied    bool   `json:"reapplied"`
				ReapplyError string `json:"reapplyError"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusInternalServerError || body.Error == "" || body.Detail == "" || !body.Restored || body.Reapplied != (mode == "nft") || (body.ReapplyError != "") != (mode != "nft") {
				t.Fatalf("failure response: %d %s", rec.Code, rec.Body)
			}
			if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("X-Containd-Warnings") != "" {
				t.Fatalf("failure cleared auth or downgraded error: %v", rec.Header())
			}
			if revoked {
				t.Fatal("failed reset revoked SSH connections")
			}
			if engine.blockClears != 0 {
				t.Fatal("failed reset cleared dynamic blocks")
			}
			got, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(jsonValue(t, running), jsonValue(t, got)) {
				t.Fatalf("running changed: %+v %v", got, err)
			}
			staged, err := store.LoadCandidate(ctx)
			if err != nil || !reflect.DeepEqual(jsonValue(t, candidate), jsonValue(t, staged)) {
				t.Fatalf("candidate changed: %+v %v", staged, err)
			}
			bank, err := store.LoadIDSRules(ctx)
			if err != nil || !reflect.DeepEqual(running.IDS.Rules, bank) {
				t.Fatalf("IDS bank changed: %+v %v", bank, err)
			}
			gotUser, err := userStore.GetByID(ctx, user.ID)
			if err != nil || !reflect.DeepEqual(beforeUser, gotUser) {
				t.Fatalf("user credentials/MFA changed: %+v %v", gotUser, err)
			}
			gotSession, err := userStore.GetSession(ctx, sess.ID)
			if err != nil || !reflect.DeepEqual(sess, gotSession) {
				t.Fatalf("session changed: %+v %v", gotSession, err)
			}
			records, err := auditStore.List(ctx, 10)
			if err != nil || len(records) != 2 {
				t.Fatalf("audit history lost: %+v %v", records, err)
			}
			found := false
			for _, record := range records {
				found = found || record.Action == "pre.reset"
			}
			if !found {
				t.Fatal("pre-reset audit record wiped")
			}
			if mode != "dataplane" && len(engine.attempts) != 2 {
				t.Fatalf("runtime recovery not attempted: %+v", engine.attempts)
			}
			if err := testRollback(store, ctx); err != nil {
				t.Fatal(err)
			}
			previous, err := store.Load(ctx)
			if err != nil || previous.System.Hostname != "running" {
				t.Fatalf("previous lost: %+v %v", previous, err)
			}
		})
	}
}

func TestFactoryResetApplyErrorReportsRecoveryFailures(t *testing.T) {
	router := gin.New()
	router.POST("/", func(c *gin.Context) {
		factoryResetApplyError(c, &config.ApplyError{
			Err:          errors.New("runtime failed"),
			RestoreError: errors.New("restore failed"),
			ReapplyError: errors.New("reapply not attempted"),
			HealthError:  errors.New("health write failed"),
		})
	})
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodPost, "/", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError || body["restored"] != false || body["reapplied"] != false || body["restoreError"] != "restore failed" || body["reapplyError"] != "reapply not attempted" || body["healthError"] != "health write failed" {
		t.Fatalf("recovery reporting: %d %s", rec.Code, rec.Body)
	}
}

func TestFactoryResetSuccessReplacesConfigurationAndUsers(t *testing.T) {
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
	t.Setenv("CONTAIND_LAB_MODE", "")
	ctx := context.Background()
	store := stageStore(t)
	if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	candidate := config.DefaultConfig()
	candidate.System.Hostname = "discard-me"
	candidate.IDS.Rules = []config.IDSRule{}
	if err := testSaveCandidate(store, ctx, candidate); err != nil {
		t.Fatal(err)
	}
	userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer userStore.Close()
	user, err := userStore.Create(ctx, users.User{Username: "old-admin", Role: "admin"}, "StrongPassword123")
	if err != nil {
		t.Fatal(err)
	}
	session, err := userStore.CreateSession(ctx, user.ID, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	engine := &mockEngine{}
	router := gin.New()
	router.GET("/api/v1/config/candidate", getCandidateConfigHandler(store))
	router.POST("/", factoryResetHandler(store, userStore, engine, nil))
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`))))
	if rec.Code != http.StatusOK || rec.Header().Get("X-Containd-Warnings") != "" {
		t.Fatalf("reset failed: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	if engine.blockClears != 1 {
		t.Fatalf("dynamic blocks cleared %d times, want 1", engine.blockClears)
	}
	running, err := store.Load(ctx)
	if err != nil || running.System.Hostname != "containd" {
		t.Fatalf("defaults not saved: %+v %v", running, err)
	}
	staged, err := store.LoadCandidate(ctx)
	if err != nil || staged.System.Hostname != "containd" {
		t.Fatalf("old candidate retained: %+v %v", staged, err)
	}
	bank, err := store.LoadIDSRules(ctx)
	wantBank := config.DefaultIDSConfig().Rules
	sort.Slice(wantBank, func(i, j int) bool { return wantBank[i].ID < wantBank[j].ID })
	if err != nil || !reflect.DeepEqual(jsonValue(t, wantBank), jsonValue(t, bank)) {
		t.Fatalf("default IDS bank not installed: %+v %v", bank, err)
	}
	if err := testRollback(store, ctx); !errors.Is(err, config.ErrNotFound) {
		t.Fatalf("old history retained: %v", err)
	}
	gotUsers, err := userStore.List(ctx)
	if err != nil || len(gotUsers) != 1 || gotUsers[0].ID == user.ID {
		t.Fatalf("users not replaced: %+v %v", gotUsers, err)
	}
	if gotUsers[0].Username != "containd" {
		t.Fatalf("default admin not seeded: %+v", gotUsers[0])
	}
	if _, err := userStore.GetSession(ctx, session.ID); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("old session retained: %v", err)
	}
}
