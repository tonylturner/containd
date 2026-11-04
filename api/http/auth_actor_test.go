// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestAuthenticatedActor(t *testing.T) {
	for _, tc := range []struct {
		name, bootstrap, username, want string
		lab, unsigned, nilStore         bool
		legacy                          string
		automation                      bool
	}{
		{name: "session", username: "session-admin", want: "session-admin"},
		{name: "lab subject", lab: true, username: "local-admin", want: "local-admin"},
		{name: "lab bootstrap account", lab: true, unsigned: true, bootstrap: "bootstrap-admin", username: "bootstrap-admin", want: "bootstrap-admin"},
		{name: "lab automation", lab: true, bootstrap: "bootstrap-admin", want: "bootstrap-admin"},
		{name: "lab automation account", lab: true, bootstrap: "bootstrap-admin", username: "bootstrap-admin", automation: true, want: "bootstrap-admin"},
		{name: "lab missing default account", lab: true, want: "containd"},
		{name: "lab no store", lab: true, nilStore: true, bootstrap: "bootstrap-admin", want: "bootstrap-admin"},
		{name: "lab default", lab: true, nilStore: true, want: "containd"},
		{name: "lab unsigned", lab: true, unsigned: true, nilStore: true, want: "containd"},
		{name: "legacy admin", legacy: "admin", nilStore: true, want: "legacy-admin-token"},
		{name: "legacy auditor", legacy: "auditor", nilStore: true, want: "legacy-auditor-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_LAB_MODE", "0")
			if tc.lab {
				t.Setenv("CONTAIND_LAB_MODE", "1")
			}
			t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", tc.bootstrap)
			t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
			if tc.unsigned || tc.legacy != "" {
				t.Setenv("CONTAIND_JWT_SECRET", "")
			}
			t.Setenv("CONTAIND_ADMIN_TOKEN", "admin-token")
			t.Setenv("CONTAIND_AUDITOR_TOKEN", "auditor-token")
			us := newMockUserStore()
			token := signTestJWT([]byte(testJWTSecret), "automation", "untrusted-claim", "admin", "", time.Now().Add(time.Hour))
			if tc.username != "" {
				localToken, _ := addTestUser(us, []byte(testJWTSecret), "local-user", tc.username, "admin", false)
				if !tc.automation {
					token = localToken
				}
			}
			if tc.legacy != "" {
				token = tc.legacy + "-token"
			}
			var store users.Store = us
			if tc.nilStore {
				store = nil
			}
			actors := make(chan string, 1)
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || len(body) == 0 || r.Method != http.MethodPost || r.URL.Path != "/internal/learn/suggestions/one/review" {
					t.Errorf("unexpected engine request: %s %s %q, %v", r.Method, r.URL.Path, body, err)
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				actor := r.Header.Get("X-Containd-Review-Actor")
				actors <- actor
				if actor == "" {
					http.Error(w, "authenticated actor required", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"one"}`))
			}))
			defer engine.Close()
			server := NewServerWithEngineAndServices(&mockStore{}, &mockAuditStore{}, engineapi.NewHTTPClient(engine.URL), nil, store)
			for _, spoof := range []string{"", "spoofed-admin"} {
				req := jwtAuthedRequest(http.MethodPost, "/api/v1/learn/suggestions/one/review",
					bytes.NewBufferString(`{"selection":{"id":"one","revision":1}}`), token)
				req.Header.Set("X-User", spoof)
				req.Header.Set("X-Containd-Review-Actor", "spoofed-internal-actor")
				rec := httptest.NewRecorder()
				server.ServeHTTP(rec, req)
				wantStatus := http.StatusOK
				if tc.legacy == "auditor" {
					wantStatus = http.StatusForbidden
				}
				if rec.Code != wantStatus {
					t.Fatalf("suggestion response = %d %s, want %d", rec.Code, rec.Body, wantStatus)
				}
				if wantStatus == http.StatusOK {
					select {
					case actor := <-actors:
						if actor != tc.want {
							t.Fatalf("engine actor = %q, want %q", actor, tc.want)
						}
					default:
						t.Fatal("request did not reach engine")
					}
				}
			}
			// Audit attribution must not depend on middleware ordering.
			for _, auditFirst := range []bool{false, true} {
				audits := &mockAuditStore{}
				router := gin.New()
				if auditFirst {
					router.Use(withAuditStore(audits), authMiddleware(store))
				} else {
					router.Use(authMiddleware(store), withAuditStore(audits))
				}
				router.GET("/", func(c *gin.Context) {
					auditLog(c, audit.Record{Action: "test"})
					c.Status(http.StatusNoContent)
				})
				req := jwtAuthedRequest(http.MethodGet, "/", nil, token)
				req.Header.Set("X-User", "spoofed-admin")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusNoContent || len(audits.records) != 1 || audits.records[0].Actor != tc.want {
					t.Fatalf("auditFirst=%v: response=%d records=%+v, want actor %q", auditFirst, rec.Code, audits.records, tc.want)
				}
			}
		})
	}
}

func TestUnauthenticatedAuditActorIgnoresHeader(t *testing.T) {
	for _, middleware := range []bool{false, true} {
		audits := &mockAuditStore{}
		router := gin.New()
		if middleware {
			router.Use(withAuditStore(audits))
		}
		router.GET("/", func(c *gin.Context) {
			if !middleware {
				c.Set("auditStore", audits)
			}
			auditLog(c, audit.Record{Action: "test"})
			c.Status(http.StatusNoContent)
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-User", "spoofed-admin")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent || len(audits.records) != 1 || audits.records[0].Actor != "unknown" {
			t.Fatalf("middleware=%v: response=%d records=%+v", middleware, rec.Code, audits.records)
		}
	}
}
