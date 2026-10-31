// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"container/list"
	"crypto/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	cliTicketTTL    = 30 * time.Second
	ctxCLITicketKey = "cliTicket"
)

type cliIdentity struct {
	user, role, session, actor string
}

func cliIdentityFor(c *gin.Context) cliIdentity {
	return cliIdentity{
		user: c.GetString(ctxUserKey), role: c.GetString(ctxRoleKey),
		session: c.GetString(ctxSessionKey), actor: c.GetString("actor"),
	}
}

type cliTicket struct {
	key      string
	identity cliIdentity
	// Kept only in process memory, for reauthentication and CLI loopback calls.
	credential string
	expires    time.Time
}

type cliTickets struct {
	mu      sync.Mutex
	pending map[string]*list.Element
	expiry  list.List
	now     func() time.Time
}

func newCLITickets() *cliTickets {
	return &cliTickets{pending: make(map[string]*list.Element), now: time.Now}
}

// Cleanup is lazy on both issuance and redemption: no background worker or
// shutdown lifecycle is needed. A fixed TTL and monotonic issuance clock under
// the mutex put entries in expiry order. Cleanup checks only the head plus expired
// entries; each is removed at most once, giving amortised O(1) work per issuance.
func (t *cliTickets) cleanup(now time.Time) {
	for front := t.expiry.Front(); front != nil; front = t.expiry.Front() {
		ticket := front.Value.(cliTicket)
		if now.Before(ticket.expires) {
			return
		}
		delete(t.pending, ticket.key)
		t.expiry.Remove(front)
	}
	if len(t.pending) == 0 {
		// Release the map's high-water allocation after an expired burst.
		t.pending = make(map[string]*list.Element)
	}
}

func (t *cliTickets) issue() gin.HandlerFunc {
	return func(c *gin.Context) {
		t.mu.Lock()
		now := t.now()
		t.cleanup(now)
		// crypto/rand.Text supplies at least 128 bits without URL metacharacters.
		key := rand.Text()
		credential := bearerOrCookie(c)
		if refreshed := c.Writer.Header().Get("X-Auth-Token"); refreshed != "" {
			credential = refreshed
		}
		t.pending[key] = t.expiry.PushBack(cliTicket{
			key: key, identity: cliIdentityFor(c), credential: credential,
			expires: now.Add(cliTicketTTL),
		})
		t.mu.Unlock()
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"ticket": key, "expiresIn": int(cliTicketTTL.Seconds())})
	}
}

func (t *cliTickets) redeem() gin.HandlerFunc {
	return func(c *gin.Context) {
		t.mu.Lock()
		t.cleanup(t.now())
		entry, ok := t.pending[c.Query("ticket")]
		var ticket cliTicket
		if ok {
			ticket = entry.Value.(cliTicket)
			t.expiry.Remove(entry)
		}
		delete(t.pending, c.Query("ticket"))
		t.mu.Unlock()
		if !ok {
			abortJSON(c, http.StatusUnauthorized, "invalid console ticket")
			return
		}
		// The ticket is the only upgrade credential. Ignore any unrelated
		// browser cookie or Authorization header; normal auth runs again with
		// the issuer's credential to enforce revocation and account restrictions.
		c.Request.Header.Set("Authorization", "Bearer "+ticket.credential)
		c.Set(ctxCLITicketKey, ticket.identity)
		c.Next()
	}
}

func verifyCLITicketIdentity(c *gin.Context) {
	expected, ok := c.Get(ctxCLITicketKey)
	if !ok || expected != cliIdentityFor(c) {
		abortJSON(c, http.StatusUnauthorized, "console identity changed")
		return
	}
	c.Next()
}
