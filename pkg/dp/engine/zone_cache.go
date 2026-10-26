// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// zoneCache resolves the zones of addresses from the networks of a
// snapshot's zone interfaces, read from the engine's network namespace.
// The index it builds is reused while a watcher (watch) is subscribed to
// the namespace's link and address changes: every change it receives, a
// lost notification, and every subscription or unsubscription moves the
// generation, and an index built under an older generation is rebuilt.
// Without a subscription, before Start, between runs, after a failed
// subscription or on platforms without one, every lookup reads the
// interfaces again.
//
// An index is current from when it is built: a change that happens after
// the read waits in the subscribed socket and moves the generation once
// the watcher receives it. Until then, lookups see the networks from
// before the change.
//
// The zero value reads the OS interfaces.
type zoneCache struct {
	// addrsFor reads an interface's addresses; nil is the OS lookup
	// (interfaceAddrs).
	addrsFor func(string) ([]net.Addr, error)

	gen     atomic.Uint64
	watched atomic.Bool
	current atomic.Pointer[cachedZones]
}

// cachedZones is the zone index of one snapshot, built under generation
// gen.
type cachedZones struct {
	snap  *rules.Snapshot
	gen   uint64
	index zoneIndex
}

// resolve returns the zones of the source and destination addresses under
// snap.
func (c *zoneCache) resolve(snap *rules.Snapshot, srcIP, dstIP net.IP) (string, string) {
	zones := c.index(snap)
	return zones.zoneFor(srcIP), zones.zoneFor(dstIP)
}

// index returns the zone index of snap's zone interfaces.
func (c *zoneCache) index(snap *rules.Snapshot) zoneIndex {
	if !c.watched.Load() {
		return c.build(snap)
	}
	gen := c.gen.Load()
	if cur := c.current.Load(); cur != nil && cur.snap == snap && cur.gen == gen {
		return cur.index
	}
	index := c.build(snap)
	c.current.Store(&cachedZones{snap: snap, gen: gen, index: index})
	return index
}

func (c *zoneCache) build(snap *rules.Snapshot) zoneIndex {
	addrsFor := c.addrsFor
	if addrsFor == nil {
		addrsFor = interfaceAddrs
	}
	return newZoneIndex(snap, addrsFor)
}

// subscribed is called by the watcher once its subscription is in place,
// before it reads any notification: indexes built from now on are current
// until it reports a change.
func (c *zoneCache) subscribed() {
	c.gen.Add(1)
	c.watched.Store(true)
}

// changed is called by the watcher for every notification it receives and
// when notifications were lost.
func (c *zoneCache) changed() {
	c.gen.Add(1)
}

// unsubscribed is called by the watcher when it stops receiving
// notifications.
func (c *zoneCache) unsubscribed() {
	c.watched.Store(false)
	c.gen.Add(1)
}
