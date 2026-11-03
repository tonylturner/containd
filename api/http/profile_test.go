// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/profile"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// Profile selection is immutable process state, so each profile gets a process.
func TestProfileHTTP(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_PROFILE_HTTP") != "1" {
		for _, name := range []string{"training", "strict"} {
			t.Run(name, func(t *testing.T) {
				t.Setenv(profile.EnvVar, name)
				t.Setenv("CONTAIND_TEST_PROFILE_HTTP", "1")
				cmd := exec.Command(os.Args[0], "-test.run=^TestProfileHTTP$", "-test.v")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
			})
		}
		return
	}
	carriedStore := stageStore(t)
	carried, err := carriedStore.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	off := false
	carried.System.SSH.ShellMode = "linux"
	carried.System.Mgmt.EnableHTTPS, carried.System.Mgmt.EnableHSTS = &off, &off
	if err := carriedStore.Save(context.Background(), carried); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_LAB_MODE", "0")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
	t.Run("Cookie", testProfileCookie)
	t.Run("HealthMeHSTS", testProfileHealthMeHSTS)
	t.Run("TLS", testProfileTLS)
	t.Run("Import", func(t *testing.T) { testProfileImport(t, carriedStore) })
	t.Run("FactoryReset", testProfileFactoryReset)
}

func testProfileCookie(t *testing.T) {
	router := gin.New()
	router.GET("/tls", getTLSHandler(&mockStore{cfg: config.DefaultConfig()}))
	for _, tc := range []struct {
		env, policy, source string
	}{
		{"", "https-only", "default"},
		{" \t", "https-only", "default"},
		{"0", "never", "environment"},
		{"false", "never", "environment"},
		{"1", "always", "environment"},
		{"true", "always", "environment"},
		{" TRUE ", "always", "environment"},
		{"invalid", "never", "environment"},
	} {
		t.Setenv("CONTAIND_COOKIE_SECURE", tc.env)
		policy, source := tc.policy, tc.source
		if profile.IsStrict() {
			policy, source = "always", "profile"
		}
		for _, https := range []bool{false, true} {
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/tls", nil)
			if https {
				ctx.Request.TLS = &tls.ConnectionState{}
			}
			want := policy == "always" || policy == "https-only" && https
			if got := cookieSecure(ctx); got != want {
				t.Fatalf("env=%q tls=%t: got %t want %t", tc.env, https, got, want)
			}
			setAuthCookie(ctx, "token", time.Now().Add(time.Hour))
			clearAuthCookie(ctx)
			for _, cookie := range rec.Result().Cookies() {
				if cookie.Secure != want {
					t.Fatalf("cookie Secure=%t want %t", cookie.Secure, want)
				}
			}
			// Status must report the same policy over HTTP and HTTPS, not
			// the Secure flag chosen for the status request itself.
			status := httptest.NewRecorder()
			router.ServeHTTP(status, ctx.Request)
			var got map[string]any
			if err := json.Unmarshal(status.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if status.Code != http.StatusOK || got["secureCookies"] != policy || got["secureCookiesSource"] != source {
				t.Fatalf("env=%q tls=%t: policy=%s source=%s: %d %s", tc.env, https, policy, source, status.Code, status.Body)
			}
		}
	}
}

func testProfileHealthMeHSTS(t *testing.T) {
	router := NewServer(nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.TLS = &tls.ConnectionState{}
	router.ServeHTTP(rec, req)
	assertProfileResponse(t, rec)
	// HSTS belongs to the management TLS wrapper, not the Gin server.
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("duplicate Gin HSTS: %q", got)
	}
	for _, withUser := range []bool{false, true} {
		var store users.Store
		var uid string
		if withUser {
			us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = us.Close() })
			if err := us.EnsureDefaultAdmin(context.Background()); err != nil {
				t.Fatal(err)
			}
			u, err := us.GetByUsername(context.Background(), "containd")
			if err != nil {
				t.Fatal(err)
			}
			store, uid = us, u.ID
		}
		router := gin.New()
		router.GET("/me", func(c *gin.Context) { c.Set(ctxUserKey, uid) }, meHandler(store))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/me", nil))
		assertProfileResponse(t, rec)
	}
}

func assertProfileResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got["profile"] != string(profile.Current()) {
		t.Fatalf("profile response: %d %s (%v)", rec.Code, rec.Body, err)
	}
}

func testProfileTLS(t *testing.T) {
	off, on := false, true
	for _, saved := range []*bool{nil, &off, &on} {
		cfg := config.DefaultConfig()
		cfg.System.Mgmt.EnableHTTP, cfg.System.Mgmt.EnableHTTPS, cfg.System.Mgmt.EnableHSTS = saved, saved, saved
		router := gin.New()
		router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%d %s (%v)", rec.Code, rec.Body, err)
		}
		for _, field := range []string{"httpEnabled", "httpsEnabled", "hstsEnabled"} {
			want := saved == nil || *saved
			source := "default"
			if saved != nil {
				source = "config"
			}
			if profile.IsStrict() {
				want = field != "httpEnabled"
			}
			overridden := want != (saved == nil || *saved)
			if overridden {
				source = "profile"
			}
			if got[field] != want || got[field+"Source"] != source {
				t.Fatalf("%s: %s", field, rec.Body)
			}
			value, present := got[field+"Saved"]
			if present != overridden || present && value != (saved == nil || *saved) {
				t.Fatalf("%s saved value: %s", field, rec.Body)
			}
		}
		if cfg.System.Mgmt.EnableHTTP != saved || cfg.System.Mgmt.EnableHTTPS != saved {
			t.Fatal("status mutated saved configuration")
		}
	}
}

func testProfileImport(t *testing.T, carriedStore *config.SQLiteStore) {
	store := stageStore(t)
	router := gin.New()
	router.POST("/import", importConfigHandler(store))
	router.POST("/validate", validateConfigHandler(store))
	for _, field := range []string{"shell", "https", "hsts"} {
		cfg := config.DefaultConfig()
		off := false
		switch field {
		case "shell":
			cfg.System.SSH.ShellMode = "linux"
		case "https":
			cfg.System.Mgmt.EnableHTTPS = &off
		case "hsts":
			cfg.System.Mgmt.EnableHSTS = &off
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		before := testBaseRevision(store, context.Background())
		for _, route := range []string{"/import", "/validate"} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, route, bytes.NewReader(data))))
			want := http.StatusOK
			if profile.IsStrict() {
				want = http.StatusBadRequest
			}
			if rec.Code != want || profile.IsStrict() && !strings.Contains(rec.Body.String(), "CONTAIND_PROFILE=strict") {
				t.Fatalf("%s %s: %d %s", route, field, rec.Code, rec.Body)
			}
		}
		if profile.IsStrict() && testBaseRevision(store, context.Background()) != before {
			t.Fatal("refused import changed revision")
		}
	}
	carried, err := carriedStore.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	carried.Description = "import unrelated edit over weak saved intent"
	data, err := json.Marshal(carried)
	if err != nil {
		t.Fatal(err)
	}
	router = gin.New()
	router.POST("/import", importConfigHandler(carriedStore))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withTestRevision(carriedStore, httptest.NewRequest(http.MethodPost, "/import", bytes.NewReader(data))))
	if rec.Code != http.StatusOK {
		t.Fatalf("carried import: %d %s", rec.Code, rec.Body)
	}
	if err := testCommit(carriedStore, context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := carriedStore.Load(context.Background())
	if err != nil || saved.System.SSH.ShellMode != "linux" || *saved.System.Mgmt.EnableHTTPS || *saved.System.Mgmt.EnableHSTS {
		t.Fatalf("projection persisted: %+v %v", saved, err)
	}
	if err := carriedStore.Save(context.Background(), config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, withTestRevision(carriedStore, httptest.NewRequest(http.MethodPost, "/import", bytes.NewReader(data))))
	want := http.StatusOK
	if profile.IsStrict() {
		want = http.StatusBadRequest
	}
	if rec.Code != want {
		t.Fatalf("import after repair: %d %s", rec.Code, rec.Body)
	}
}

func testProfileFactoryReset(t *testing.T) {
	ctx := context.Background()
	store := stageStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "users.db")
	t.Setenv("CONTAIND_USERS_DB", path)
	us, err := users.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = us.Close() })
	as, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Close() })
	if err := as.Add(ctx, audit.Record{Action: "before.reset"}); err != nil {
		t.Fatal(err)
	}
	ledger := &users.BootstrapLedger{}
	// Seed only secret-free metadata: issuance and delivery are users/mgmt
	// responsibilities. The reset must publish this after wiping audit.
	ledger.Append(users.BootstrapMetadata{Username: "containd", Generation: 42, Reason: "reset"})
	router := gin.New()
	router.Use(withAuditStore(as))
	engine := &mockEngine{}
	router.POST("/reset", testRuntimeHandler(t, store, engine, nil, factoryResetWithLedger(store, us, engine, nil, ledger)))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withTestRevision(store, httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(`{"confirm":"NUCLEAR"}`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if profile.IsStrict() {
		if strings.Contains(rec.Body.String(), "default credentials") || !strings.Contains(rec.Body.String(), filepath.Join(dir, "bootstrap", "admin-password")) {
			t.Fatalf("strict reset instructions: %s", rec.Body)
		}
	} else if !strings.Contains(rec.Body.String(), "default credentials") {
		t.Fatalf("training reset instructions: %s", rec.Body)
	}
	records, err := as.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		if record.Action == "before.reset" {
			t.Fatal("audit was not wiped")
		}
		found = found || record.Action == "auth.bootstrap_password.issued" && record.Target == "containd" && record.Detail == "generation=42 reason=reset"
	}
	if !found || ledger.Drain() != nil {
		t.Fatalf("bootstrap audit after wipe: %+v", records)
	}
}
