// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"container/list"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// ReasonRecentlyInfected marks a request refused from the blocked-URL
// memory: the same client fetched the same URL from the same origin
// recently and the response was Infected. The verdict is Infected, the
// signature the remembered one and Backend "gate".
const ReasonRecentlyInfected avscan.Reason = "recently_infected_url"

// recentlyInfectedDetail is the Detail of a memory refusal.
const recentlyInfectedDetail = "blocked: recently infected URL"

// urlKey identifies one download for the blocked-URL memory: the client,
// the effective origin, the authority and the path with its query.
type urlKey struct {
	client netip.Addr
	server netip.AddrPort
	host   string
	path   string
}

// blockedEntry is one remembered infected URL.
type blockedEntry struct {
	key       urlKey
	signature string
	expires   time.Time
}

// blockedURLs remembers URLs whose download was Infected so that a later
// request for one is refused before the origin is contacted: a client
// that received the streamed prefix cannot fetch the rest with a Range
// request, which would be a partial object and so unscanned. Entries
// expire after their TTL and the oldest goes when the bound is reached.
type blockedURLs struct {
	mu      sync.Mutex
	entries map[urlKey]*list.Element
	order   *list.List
}

func newBlockedURLs() *blockedURLs {
	return &blockedURLs{entries: map[urlKey]*list.Element{}, order: list.New()}
}

// add remembers key for ttl, keeping at most limit entries.
func (b *blockedURLs) add(key urlKey, signature string, ttl time.Duration, limit int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.entries[key]; ok {
		b.order.MoveToBack(e)
		e.Value = &blockedEntry{key: key, signature: signature, expires: time.Now().Add(ttl)}
		return
	}
	for b.order.Len() >= limit {
		b.remove(b.order.Front())
	}
	b.entries[key] = b.order.PushBack(&blockedEntry{key: key, signature: signature, expires: time.Now().Add(ttl)})
}

// lookup reports whether key is remembered and unexpired, with its
// signature. An expired entry is dropped on the way.
func (b *blockedURLs) lookup(key urlKey) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[key]
	if !ok {
		return "", false
	}
	entry := e.Value.(*blockedEntry)
	if !time.Now().Before(entry.expires) {
		b.remove(e)
		return "", false
	}
	return entry.signature, true
}

func (b *blockedURLs) remove(e *list.Element) {
	delete(b.entries, e.Value.(*blockedEntry).key)
	b.order.Remove(e)
}

func (b *blockedURLs) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.order.Len()
}

// urlKey is the memory key of the transaction's request.
func (tx *transaction) urlKey() urlKey {
	return urlKey{
		client: tx.c.clientAddr.Addr(),
		server: tx.c.serverAddr,
		host:   strings.ToLower(tx.req.host),
		path:   requestPath(tx.req.target),
	}
}

// requestPath is the path and query of a request target: an absolute-form
// target loses its scheme and authority so both forms of the same URL
// share one key.
func requestPath(target string) string {
	if _, ok := absoluteAuthority(target); !ok {
		return target
	}
	_, rest, _ := strings.Cut(target, "://")
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		return rest[i:]
	}
	return "/"
}

// remember records an Infected download so that a repeat fetch is refused.
func (tx *transaction) remember(res avscan.Result) {
	if res.Verdict != avscan.Infected {
		return
	}
	tx.c.srv.blocked.add(tx.urlKey(), res.Signature, tx.set.BlockedURLTTL, tx.set.BlockedURLEntries)
}

// refuseRemembered refuses the request when the memory holds its URL and
// reports whether it did.
func (tx *transaction) refuseRemembered() bool {
	signature, ok := tx.c.srv.blocked.lookup(tx.urlKey())
	if !ok {
		return false
	}
	res := avscan.Result{
		Verdict: avscan.Infected, Reason: ReasonRecentlyInfected, Signature: signature,
		Backend: "gate", Detail: recentlyInfectedDetail,
	}
	tx.emit(avscan.Download, res, avscan.Block, 0, nil, false, 0)
	tx.c.refuse(refusal(403, "Forbidden", "containd blocked this request: recently infected URL\n", tx.headOnly()), true)
	return true
}
