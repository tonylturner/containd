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
	"github.com/golang-jwt/jwt/v5"
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
				// replace its identity and remove every session record. Lab
				// tokens intentionally remain usable without those records.
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
				protected.GET("/api/v1/config/candidate", getCandidateConfigHandler(store))
				protected.POST("/reset", factoryResetHandler(store, us, engine, services, func(_ context.Context, initiator string) { revoked = initiator }))
				rec := httptest.NewRecorder()
				serveWithConfigRevision(t, router, rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, token))
				if rec.Code != http.StatusOK {
					t.Fatalf("initial auth: %d %s", rec.Code, rec.Body)
				}
				rec = httptest.NewRecorder()
				resetReq := jwtAuthedRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`), token)
				withTestRevision(store, resetReq)
				resetReq.Header.Set("X-Containd-SSH-Connection", "initiating-ssh-connection")
				serveWithConfigRevision(t, router, rec, resetReq)
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
				wantInitiator := sess.ID
				if lab {
					wantInitiator = "initiating-ssh-connection"
				}
				if strings.Contains(body.Message, "Lab web/API tokens remain valid") != lab {
					t.Fatalf("incorrect lab token revocation message: %q", body.Message)
				}
				if (rec.Header().Get("X-Containd-Warnings") != "") != warning || revoked != wantInitiator {
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
				serveWithConfigRevision(t, router, rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, token))
				wantStatus := http.StatusUnauthorized
				if lab {
					wantStatus = http.StatusOK
				}
				if rec.Code != wantStatus {
					t.Fatalf("old JWT status: got %d want %d body=%s", rec.Code, wantStatus, rec.Body)
				}
				rec = httptest.NewRecorder()
				serveWithConfigRevision(t, router, rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":"containd","password":"containd"}`))))
				var login loginResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &login); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusOK || login.Token == "" {
					t.Fatalf("default credential login failed: %d %s", rec.Code, rec.Body)
				}
				rec = httptest.NewRecorder()
				serveWithConfigRevision(t, router, rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, login.Token))
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

func TestFactoryResetPreservesRangerDangerLabToken(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	store := stageStore(t)
	us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	if err := us.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	// RangerDanger signs its own tokens without a user ID or session jti.
	sign := func(secret string, expires time.Time) string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":  "rangerdanger-backend",
			"role": "admin",
			"exp":  expires.Unix(),
		}).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	token := sign(testJWTSecret, time.Now().Add(24*time.Hour))
	invalidSignature := sign(testJWTSecret+"-different", time.Now().Add(24*time.Hour))
	expired := sign(testJWTSecret, time.Now().Add(-time.Hour))
	router := NewServerWithEngineAndServices(store, nil, &mockEngine{}, nil, us)
	checkAuth := func() {
		t.Helper()
		for _, tc := range []struct {
			token string
			want  int
		}{
			{token, http.StatusOK},
			{invalidSignature, http.StatusUnauthorized},
			{expired, http.StatusUnauthorized},
		} {
			rec := httptest.NewRecorder()
			serveWithConfigRevision(t, router, rec, jwtAuthedRequest(http.MethodGet, "/api/v1/auth/session", nil, tc.token))
			if rec.Code != tc.want {
				t.Fatalf("lab token authentication: got %d want %d body=%s", rec.Code, tc.want, rec.Body)
			}
			if tc.want == http.StatusOK {
				var body struct {
					Role      string `json:"role"`
					SessionID string `json:"sessionId"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Role != "admin" || body.SessionID != "lab" {
					t.Fatalf("lab context changed: %+v", body)
				}
			}
		}
	}
	checkAuth()
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, jwtAuthedRequest(http.MethodPost, "/api/v1/system/factory-reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`), token))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Lab web/API tokens remain valid") {
		t.Fatalf("reset with session-less lab token: %d %s", rec.Code, rec.Body)
	}
	checkAuth()
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
	router.GET("/api/v1/config/candidate", getCandidateConfigHandler(store))
	router.POST("/reset", factoryResetHandler(store, us, &mockEngine{}, nil))
	router.GET("/auth/me", func(c *gin.Context) { c.Status(http.StatusOK) })
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, withTestRevision(store, jwtAuthedRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`), "lab")))
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, jwtAuthedRequest(http.MethodGet, "/auth/me", nil, "lab"))
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
	router.GET("/api/v1/config/candidate", getCandidateConfigHandler(store))
	router.POST("/reset", factoryResetHandler(store, us, &mockEngine{}, nil))
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`))))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "audit reset:") || strings.Contains(rec.Body.String(), "completed") {
		t.Fatalf("audit cleanup failure hidden: %d %s", rec.Code, rec.Body)
	}
}

// A reset whose block clear fails is applied, but the blocks it could not
// remove stay in force: the response must report incomplete convergence.
func TestFactoryResetReportsDynamicBlockClearFailure(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	store := stageStore(t)
	us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	engine := &mockEngine{clearErr: errors.New("engine blocks clear status 502: nft: netlink busy")}
	router := gin.New()
	router.GET("/api/v1/config/candidate", getCandidateConfigHandler(store))
	router.POST("/reset", factoryResetHandler(store, us, engine, nil))
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, router, rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`))))
	var body struct {
		Warnings []string `json:"warnings"`
		Message  string   `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := "dynamic blocks: engine blocks clear status 502: nft: netlink busy"
	if rec.Code != http.StatusOK || engine.blockClears != 1 || !reflect.DeepEqual(body.Warnings, []string{want}) ||
		rec.Header().Get("X-Containd-Warnings") != want || strings.Contains(body.Message, "completed") || !strings.Contains(body.Message, want) {
		t.Fatalf("block clear failure hidden: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	admins, err := us.List(context.Background())
	if err != nil || len(admins) != 1 || admins[0].Username != "containd" {
		t.Fatalf("users not reset after an applied configuration: %+v %v", admins, err)
	}
}
