// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func decodeCLITicket(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Ticket    string `json:"ticket"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil ||
		len(body.Ticket) < 26 || body.ExpiresIn != 30 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ticket response: status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body)
	}
	return body.Ticket
}

func TestCLITicketLifetimeCapacityAndAtomicConsume(t *testing.T) {
	tickets := newCLITickets()
	now := time.Now()
	tickets.now = func() time.Time { return now }
	r := gin.New()
	r.POST("/ticket", func(c *gin.Context) { c.Set(ctxRoleKey, "view") }, tickets.issue())
	r.GET("/ws", tickets.redeem(), func(c *gin.Context) {
		expected, _ := c.Get(ctxCLITicketKey)
		if expected != (cliIdentity{role: "view"}) || c.GetHeader("Authorization") != "Bearer issuer" {
			t.Error("lost ticket identity/credential")
		}
		c.Status(http.StatusNoContent)
	})
	issue := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ticket", nil)
		req.Header.Set("Authorization", "Bearer issuer")
		r.ServeHTTP(rec, req)
		return rec
	}
	consume := func(key string) int {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws?ticket="+key, nil))
		return rec.Code
	}
	key := decodeCLITicket(t, issue())
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if consume(key) == http.StatusNoContent {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 || consume(key) != 401 || consume("unknown") != 401 || consume("") != 401 {
		t.Fatal("ticket must be consumed exactly once")
	}
	key = decodeCLITicket(t, issue())
	now = now.Add(cliTicketTTL)
	if consume(key) != 401 || len(tickets.pending) != 0 {
		t.Fatal("expired ticket accepted or retained")
	}
	for range cliTicketCapacity {
		decodeCLITicket(t, issue())
	}
	if rec := issue(); rec.Code != http.StatusServiceUnavailable || len(tickets.pending) != cliTicketCapacity {
		t.Fatal("ticket capacity not enforced")
	}
	now = now.Add(cliTicketTTL)
	decodeCLITicket(t, issue())
	if len(tickets.pending) != 1 {
		t.Fatal("issuance did not clean expired tickets")
	}
}

func TestCLITicketSessionAuth(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_LAB_MODE", "0")
	us := newMockUserStore()
	token, uid := addTestAdmin(us, []byte(testJWTSecret))
	r := setupJWTServer(&mockStore{cfg: config.DefaultConfig()}, us)
	issue := func(cookie bool) string {
		rec := httptest.NewRecorder()
		req := jwtAuthedRequest(http.MethodPost, "/api/v1/cli/ws/ticket", nil, token)
		if cookie {
			req.Header.Del("Authorization")
			req.AddCookie(&http.Cookie{Name: "containd_token", Value: token})
		}
		r.ServeHTTP(rec, req)
		return decodeCLITicket(t, rec)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cli/ws/ticket", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated ticket issuance")
	}
	cross := jwtAuthedRequest(http.MethodPost, "/api/v1/cli/ws/ticket", nil, token)
	cross.Header.Del("Authorization")
	cross.AddCookie(&http.Cookie{Name: "containd_token", Value: token})
	cross.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, cross)
	if rec.Code != http.StatusForbidden {
		t.Fatal("cross-origin cookie issuance accepted")
	}

	srv := httptest.NewServer(r)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/cli/ws"
	headers := http.Header{"Origin": {srv.URL}}
	dial := func(query string, want int) {
		t.Helper()
		conn, resp, err := websocket.DefaultDialer.Dial(wsURL+query, headers)
		if conn != nil {
			defer conn.Close()
		}
		if resp == nil || resp.StatusCode != want || (want == 101 && err != nil) {
			t.Fatalf("upgrade: resp=%v err=%v want=%d", resp, err, want)
		}
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		if conn != nil {
			// Read the greeting so the handler has finished auth before mutating the store.
			if _, _, err := conn.ReadMessage(); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, cookie := range []bool{true, false} {
		key := issue(cookie)
		dial("?ticket="+key, 101)
		dial("?ticket="+key, 401)
	}
	dial("?token="+token, 401)
	headers.Set("Cookie", "containd_token="+token)
	dial("", 401) // A valid ambient cookie is not a second upgrade path.
	headers.Del("Cookie")
	key := issue(false)
	headers.Set("Origin", "https://evil.example")
	dial("?ticket="+key, 101) // The ticket, not Origin, authorizes the upgrade.
	headers.Set("Origin", srv.URL)
	dial("?ticket="+key, 401)

	key = issue(false)
	// The actual logout route must invalidate already-issued tickets.
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, jwtAuthedRequest(http.MethodPost, "/api/v1/auth/logout", nil, token))
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body)
	}
	dial("?ticket="+key, 401)
	if !us.sessions["sess-"+uid].Revoked {
		t.Fatal("logout did not revoke session")
	}
}

func TestCLIWSProxyHostWithoutPort(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_LAB_MODE", "0")
	t.Setenv("CONTAIND_ALLOWED_ORIGINS", "http://localhost:8088")
	us := newMockUserStore()
	token, _ := addTestAdmin(us, []byte(testJWTSecret))
	r := setupJWTServer(&mockStore{cfg: config.DefaultConfig()}, us)
	// The proxy strips the published port from Host on the ticket POST too.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/ws/ticket", nil)
	req.Host = "localhost"
	req.Header.Set("Origin", "http://localhost:8088")
	req.AddCookie(&http.Cookie{Name: "containd_token", Value: token})
	r.ServeHTTP(rec, req)
	ticket := decodeCLITicket(t, rec)

	srv := httptest.NewServer(r)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/cli/ws"
	headers := http.Header{"Host": {"localhost"}, "Origin": {"http://localhost:8088"}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL+"?ticket="+ticket, headers)
	if err != nil {
		t.Fatalf("proxy upgrade: response=%v error=%v", resp, err)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("proxy upgrade: status=%d", resp.StatusCode)
	}
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://localhost:8088", ""} {
		headers.Set("Origin", origin)
		unauthed, rejected, err := websocket.DefaultDialer.Dial(wsURL, headers)
		if unauthed != nil {
			unauthed.Close()
		}
		if rejected != nil && rejected.Body != nil {
			rejected.Body.Close()
		}
		if err == nil || rejected == nil || rejected.StatusCode != http.StatusUnauthorized {
			t.Fatalf("upgrade without ticket: response=%v error=%v", rejected, err)
		}
	}
}

func TestCLITicketReauthenticationPreservesIdentity(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_LAB_MODE", "0")
	us := newMockUserStore()
	token, uid := addTestAdmin(us, []byte(testJWTSecret))
	tickets := newCLITickets()
	r := gin.New()
	r.POST("/ticket", authMiddleware(us), tickets.issue())
	r.GET("/ws", tickets.redeem(), authMiddleware(us), verifyCLITicketIdentity, func(c *gin.Context) {
		if cliIdentityFor(c) != (cliIdentity{user: uid, role: "admin", session: "sess-" + uid, actor: "containd"}) {
			t.Errorf("wrong identity: %+v", cliIdentityFor(c))
		}
		c.Status(http.StatusNoContent)
	})
	issue := func() string {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, jwtAuthedRequest(http.MethodPost, "/ticket", nil, token))
		return decodeCLITicket(t, rec)
	}
	consume := func(key string, want int) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ws?ticket="+key, nil)
		req.Header.Set("Authorization", "Bearer unrelated")
		r.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("consume: %d %s", rec.Code, rec.Body)
		}
	}
	consume(issue(), http.StatusNoContent)
	key := issue()
	us.users[uid].Role = "view"
	consume(key, http.StatusUnauthorized)
	us.users[uid].Role = "admin"
	key = issue()
	us.sessions["sess-"+uid].ExpiresAt = time.Now().Add(-time.Second)
	consume(key, http.StatusUnauthorized)
}

func TestCLITicketLabSessionlessJWT(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_LAB_MODE", "1")
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "rangerdanger-backend", "role": "admin",
		"exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	// No user/session lookup is possible: this is RangerDanger's lab contract.
	tickets := newCLITickets()
	r := gin.New()
	r.POST("/ticket", authMiddleware(nil), tickets.issue())
	r.GET("/ws", tickets.redeem(), authMiddleware(nil), verifyCLITicketIdentity, func(c *gin.Context) {
		if cliIdentityFor(c) != (cliIdentity{role: "admin"}) {
			t.Error("lab context changed")
		}
		c.Status(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, jwtAuthedRequest(http.MethodPost, "/ticket", nil, token))
	key := decodeCLITicket(t, rec)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws?ticket="+key, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("lab redemption: %d %s", rec.Code, rec.Body)
	}
}
