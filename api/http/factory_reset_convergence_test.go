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
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type resetCaptureServices struct{ config.ServicesConfig }

func (s *resetCaptureServices) Apply(_ context.Context, cfg config.ServicesConfig) error {
	s.ServicesConfig = cfg
	return nil
}

func TestFactoryResetConvergenceWarningsAndJWTRevocation(t *testing.T) {
	for _, lab := range []bool{false, true} {
		for _, warning := range []bool{false, true} {
			t.Run(fmtResetCase(lab, warning), func(t *testing.T) {
				t.Setenv("CONTAIND_LAB_MODE", "0")
				if lab {
					t.Setenv("CONTAIND_LAB_MODE", "1")
				}
				t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
				t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
				t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
				ctx := context.Background()
				store := stageStore(t)
				running, err := store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				running.Services.DNS.Enabled = true
				if err := store.Save(ctx, running); err != nil {
					t.Fatal(err)
				}
				us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer us.Close()
				// Lab auth resolves the canonical admin, while reset must
				// replace its identity and revoke every existing session.
				u, err := us.Create(ctx, users.User{Username: "containd", Role: "admin"}, "BeforeReset123")
				if err != nil {
					t.Fatal(err)
				}
				sess, err := us.CreateSession(ctx, u.ID, time.Hour, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				other, err := us.CreateSession(ctx, u.ID, time.Hour, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				token, err := signJWT(jwtSecret(), u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
				if err != nil {
					t.Fatal(err)
				}
				engine := &mockEngine{}
				if warning {
					engine.svcErr = errors.New("service runtime unavailable")
				}
				services := &resetCaptureServices{ServicesConfig: running.Services}
				revoked := ""
				router := gin.New()
				router.POST("/login", loginHandler(us))
				protected := router.Group("", authMiddleware(us))
				protected.GET("/auth/me", func(c *gin.Context) { c.Status(http.StatusOK) })
				protected.POST("/reset", factoryResetHandler(store, us, engine, services, func(_ context.Context, initiator string) { revoked = initiator }))
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, token))
				if rec.Code != http.StatusOK {
					t.Fatalf("initial auth: %d %s", rec.Code, rec.Body)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, jwtAuthedRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`), token))
				var body struct {
					Warnings []string `json:"warnings"`
					Message  string   `json:"message"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusOK || (len(body.Warnings) > 0) != warning || strings.Contains(body.Message, "completed") == warning {
					t.Fatalf("reset outcome: %d %s", rec.Code, rec.Body)
				}
				if (rec.Header().Get("X-Containd-Warnings") != "") != warning || revoked != sess.ID {
					t.Fatalf("warnings/revocation: %v %q", rec.Header(), revoked)
				}
				defaults := ApplianceDefaults(nil)
				snap, err := compile.CompileSnapshot(defaults)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(jsonValue(t, engine.snap), jsonValue(t, snap)) ||
					!reflect.DeepEqual(jsonValue(t, engine.lastDP), jsonValue(t, defaults.DataPlane)) ||
					!reflect.DeepEqual(jsonValue(t, engine.lastSvc), jsonValue(t, defaults.Services)) ||
					!reflect.DeepEqual(jsonValue(t, services.ServicesConfig), jsonValue(t, defaults.Services)) {
					t.Fatal("old policy or enabled service survived reset")
				}
				for _, sid := range []string{sess.ID, other.ID} {
					if _, err := us.GetSession(ctx, sid); !errors.Is(err, users.ErrNotFound) {
						t.Fatalf("old session survived: %s %v", sid, err)
					}
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, token))
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("old JWT accepted: %d %s", rec.Code, rec.Body)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"containd","password":"containd"}`)))
				var login loginResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &login); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusOK || login.Token == "" {
					t.Fatalf("default credential login failed: %d %s", rec.Code, rec.Body)
				}
				rec = httptest.NewRecorder()
				router.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, login.Token))
				if rec.Code != http.StatusOK {
					t.Fatalf("management unavailable after reset: %d %s", rec.Code, rec.Body)
				}
			})
		}
	}
}

func fmtResetCase(lab, warning bool) string {
	name := "production"
	if lab {
		name = "lab"
	}
	if warning {
		name += "/warning"
	} else {
		name += "/converged"
	}
	return name
}

func TestFactoryResetPreservesSecretlessLabBypass(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	store := stageStore(t)
	us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	if err := us.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(authMiddleware(us))
	router.POST("/reset", factoryResetHandler(store, us, &mockEngine{}, nil))
	router.GET("/auth/me", func(c *gin.Context) { c.Status(http.StatusOK) })
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, jwtAuthedRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`), "lab"))
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, "lab"))
	if rec.Code != http.StatusOK {
		t.Fatalf("secretless bypass changed: %d %s", rec.Code, rec.Body)
	}
}

func TestFactoryResetReportsAuditCleanupWarning(t *testing.T) {
	store := stageStore(t)
	us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	audits, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := audits.Close(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auditStore", audits)
		c.Next()
	})
	router.POST("/reset", factoryResetHandler(store, us, &mockEngine{}, nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "audit reset:") || strings.Contains(rec.Body.String(), "completed") {
		t.Fatalf("audit cleanup failure hidden: %d %s", rec.Code, rec.Body)
	}
}
