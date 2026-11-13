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
	items    map[K]*list.Element
	order    list.List
	cap      int
	onRemove func(K, V, bool)
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
		b.removeElement(e, false)
	}
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
		b.removeElement(e, true)
		(*overflow)++
	}
	v := create()
	b.items[key] = b.order.PushFront(&entry[K, V]{key, v, now})
	return v
}

func (b *bounded[K, V]) remove(key K, evicted bool) bool {
	e := b.items[key]
	if e == nil {
		return false
	}
	b.removeElement(e, evicted)
	return true
}

func (b *bounded[K, V]) removeAll(evicted bool) {
	for e := b.order.Back(); e != nil; e = b.order.Back() {
		b.removeElement(e, evicted)
	}
}

func (b *bounded[K, V]) removeElement(e *list.Element, evicted bool) {
	item := e.Value.(*entry[K, V])
	delete(b.items, item.key)
	b.order.Remove(e)
	if b.onRemove != nil {
		b.onRemove(item.key, item.value, evicted)
	}
}
