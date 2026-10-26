// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"container/list"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

const domainAssociationCapacity = 16384

type domainAssociationKey struct {
	ip   netip.Addr
	name string
}

type domainAssociation struct {
	key     domainAssociationKey
	expires time.Time
}

// domainExclusions owns the bounded association cache and decisions for tracked
// flows. Association expiry never reverses a flow decision. State identity
// keeps reused tuples independent; decisions disappear with their tracked flow.
type domainExclusions struct {
	mu           sync.Mutex
	now          func() time.Time
	capacity     int
	associations map[domainAssociationKey]*list.Element
	byIP         map[netip.Addr]map[domainAssociationKey]*list.Element
	lru          *list.List
	decisions    map[*flow.State]bool
	lastPrune    time.Time
	evictions    uint64
}

func newDomainExclusions(exclusions []DPIExclusion) *domainExclusions {
	for _, x := range exclusions {
		if x.Type == "domain" {
			return &domainExclusions{
				now: time.Now, capacity: domainAssociationCapacity,
				associations: make(map[domainAssociationKey]*list.Element), lru: list.New(),
				byIP:      make(map[netip.Addr]map[domainAssociationKey]*list.Element),
				decisions: make(map[*flow.State]bool),
			}
		}
	}
	return nil
}

func domainMatches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(name, pattern[1:]) && len(name) > len(pattern)-1
	}
	return name != "" && name == pattern
}

func (d *domainExclusions) add(ip netip.Addr, name string, ttl uint32) {
	key := domainAssociationKey{ip.Unmap(), name}
	expires := d.now().Add(max(30*time.Second, min(time.Duration(ttl)*time.Second, time.Hour)))
	if elem := d.associations[key]; elem != nil {
		elem.Value = domainAssociation{key, expires}
		d.lru.MoveToFront(elem)
		return
	}
	if len(d.associations) >= d.capacity {
		old := d.lru.Back()
		if d.now().Before(old.Value.(domainAssociation).expires) {
			d.evictions++
		}
		d.remove(old)
	}
	elem := d.lru.PushFront(domainAssociation{key, expires})
	d.associations[key] = elem
	if d.byIP[key.ip] == nil {
		d.byIP[key.ip] = make(map[domainAssociationKey]*list.Element)
	}
	d.byIP[key.ip][key] = elem
}

func (d *domainExclusions) remove(elem *list.Element) {
	key := elem.Value.(domainAssociation).key
	delete(d.associations, key)
	delete(d.byIP[key.ip], key)
	if len(d.byIP[key.ip]) == 0 {
		delete(d.byIP, key.ip)
	}
	d.lru.Remove(elem)
}

func (d *domainExclusions) lookup(ip netip.Addr) string {
	for _, elem := range d.byIP[ip.Unmap()] {
		a := elem.Value.(domainAssociation)
		if !d.now().Before(a.expires) {
			d.remove(elem)
		} else {
			d.lru.MoveToFront(elem)
			return a.key.name
		}
	}
	return ""
}
