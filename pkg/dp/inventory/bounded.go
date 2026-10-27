// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package inventory

import (
	"container/list"
	"time"
)

// MaxIdle is the fixed observation-idle retention period for inventory entries.
const MaxIdle = 24 * time.Hour

type entry[K comparable, V any] struct {
	key     K
	value   V
	touched time.Time
}

// bounded is an observation-recency LRU. Callers own synchronization; reads do
// not refresh retention. Expiry uses ingestion time, not untrusted wire time.
type bounded[K comparable, V any] struct {
	items map[K]*list.Element
	order list.List
	cap   int
}

func newBounded[K comparable, V any](cap int) *bounded[K, V] {
	return &bounded[K, V]{items: make(map[K]*list.Element), cap: cap}
}

func (b *bounded[K, V]) expire(now time.Time) {
	for e := b.order.Back(); e != nil; e = b.order.Back() {
		v := e.Value.(*entry[K, V])
		if now.Sub(v.touched) < MaxIdle {
			break
		}
		delete(b.items, v.key)
		b.order.Remove(e)
	}
}

func (b *bounded[K, V]) get(key K, now time.Time) (V, bool) {
	b.expire(now)
	if e := b.items[key]; e != nil {
		return e.Value.(*entry[K, V]).value, true
	}
	var zero V
	return zero, false
}

func (b *bounded[K, V]) observe(key K, now time.Time, create func() V, overflow *uint64) V {
	b.expire(now)
	if e := b.items[key]; e != nil {
		e.Value.(*entry[K, V]).touched = now
		b.order.MoveToFront(e)
		return e.Value.(*entry[K, V]).value
	}
	if len(b.items) == b.cap {
		e := b.order.Back()
		delete(b.items, e.Value.(*entry[K, V]).key)
		b.order.Remove(e)
		(*overflow)++
	}
	v := create()
	b.items[key] = b.order.PushFront(&entry[K, V]{key, v, now})
	return v
}
