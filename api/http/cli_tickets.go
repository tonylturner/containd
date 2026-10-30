// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"crypto/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	cliTicketTTL              = 30 * time.Second
	cliTicketCapacity         = 4096
	cliTicketIdentityCapacity = 8
	ctxCLITicketKey           = "cliTicket"
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

func (i cliIdentity) owner() string {
	if i.user != "" {
		// One account shares its quota across sessions and role changes.
		return "user:" + i.user
	}
	// Legacy tokens and store-less lab auth expose only a shared role identity.
	return "role:" + i.role
}

type cliTicket struct {
	identity cliIdentity
	// Kept only in process memory, for reauthentication and CLI loopback calls.
	credential string
	expires    time.Time
}

type cliTickets struct {
	mu      sync.Mutex
	pending map[string]cliTicket
	now     func() time.Time
}

func newCLITickets() *cliTickets {
	return &cliTickets{pending: make(map[string]cliTicket), now: time.Now}
}

// Cleanup is lazy on both issuance and redemption: no background worker or
// shutdown lifecycle is needed, and idle storage never exceeds the hard cap.
func (t *cliTickets) cleanup(now time.Time) {
	for key, ticket := range t.pending {
		if !now.Before(ticket.expires) {
			delete(t.pending, key)
		}
	}
}

func (t *cliTickets) issue() gin.HandlerFunc {
	return func(c *gin.Context) {
		t.mu.Lock()
		now := t.now()
		t.cleanup(now)
		identity := cliIdentityFor(c)
		owner := identity.owner()
		pending := 0
		for _, ticket := range t.pending {
			if ticket.identity.owner() == owner {
				pending++
			}
		}
		if pending >= cliTicketIdentityCapacity {
			t.mu.Unlock()
			apiError(c, http.StatusTooManyRequests, "too many pending console tickets for this identity")
			return
		}
		if len(t.pending) >= cliTicketCapacity {
			t.mu.Unlock()
			apiError(c, http.StatusServiceUnavailable, "console ticket capacity reached")
			return
		}
		// crypto/rand.Text supplies at least 128 bits without URL metacharacters.
		key := rand.Text()
		credential := bearerOrCookie(c)
		if refreshed := c.Writer.Header().Get("X-Auth-Token"); refreshed != "" {
			credential = refreshed
		}
		t.pending[key] = cliTicket{
			identity: identity, credential: credential,
			expires: now.Add(cliTicketTTL),
		}
		t.mu.Unlock()
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"ticket": key, "expiresIn": int(cliTicketTTL.Seconds())})
	}
}

func (t *cliTickets) redeem() gin.HandlerFunc {
	return func(c *gin.Context) {
		t.mu.Lock()
		t.cleanup(t.now())
		ticket, ok := t.pending[c.Query("ticket")]
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
