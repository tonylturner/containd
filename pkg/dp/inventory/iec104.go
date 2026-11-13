// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package inventory

import (
	"container/list"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

const (
	MaxIEC104Pairs      = 128
	MaxIEC104CAs        = 32
	MaxIEC104Points     = 256
	MaxAssets           = 1024
	MaxPeers            = 128
	MaxStationAddresses = 256
)

// IEC104Observation describes one ordered, deduplicated decoded APDU. Endpoints
// always identify the controlling client and controlled server, in either direction.
// SessionID and COT are input context only, never retained as unbounded history.
type IEC104Observation struct {
	SessionID               string
	Controlling, Controlled netip.AddrPort
	CA                      uint16
	TypeID                  uint8
	IOAs                    []uint32
	COT                     uint8
	ControlDirection        bool
	Time                    time.Time
}

type IEC104Point struct {
	IOA       uint32    `json:"ioa"`
	TypeID    uint8     `json:"typeId"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

type IEC104CA struct {
	CA                uint16        `json:"ca"`
	FirstSeen         time.Time     `json:"firstSeen"`
	LastSeen          time.Time     `json:"lastSeen"`
	AttemptedCommands uint64        `json:"attemptedCommands"`
	Points            []IEC104Point `json:"points"`
}

type IEC104Pair struct {
	Controlling       netip.AddrPort `json:"controlling"`
	Controlled        netip.AddrPort `json:"controlled"`
	FirstSeen         time.Time      `json:"firstSeen"`
	LastSeen          time.Time      `json:"lastSeen"`
	AttemptedCommands uint64         `json:"attemptedCommands"`
	CAs               []IEC104CA     `json:"cas"`
}

type InventoryOverflow struct {
	Observations     uint64 `json:"observations"`
	Pairs            uint64 `json:"pairs"`
	CAs              uint64 `json:"cas"`
	Points           uint64 `json:"points"`
	Assets           uint64 `json:"assets"`
	Peers            uint64 `json:"peers"`
	StationAddresses uint64 `json:"stationAddresses"`
}

type InventoryLimits struct {
	Pairs                    int `json:"pairs"`
	CAsPerPair               int `json:"casPerPair"`
	PointsPerCA              int `json:"pointsPerCA"`
	Assets                   int `json:"assets"`
	PeersPerAsset            int `json:"peersPerAsset"`
	StationAddressesPerAsset int `json:"stationAddressesPerAsset"`
	MaxIdleSeconds           int `json:"maxIdleSeconds"`
}

type IEC104Snapshot struct {
	Pairs    []IEC104Pair      `json:"pairs"`
	Limits   InventoryLimits   `json:"limits"`
	Overflow InventoryOverflow `json:"overflow"`
}

type pairKey struct{ controlling, controlled netip.AddrPort }
type pointKey struct {
	ioa    uint32
	typeID uint8
}
type caState struct {
	IEC104CA
	points *bounded[pointKey, *IEC104Point]
}
type pairState struct {
	IEC104Pair
	cas *bounded[uint16, *caState]
}
type iecPointRef struct {
	pair  pairKey
	ca    uint16
	point pointKey
}
type iec104Store struct {
	mu               sync.Mutex
	busyObservations atomic.Uint64
	pairs            *bounded[pairKey, *pairState]
	pointEntries     map[iecPointRef]*list.Element
	pointOrder       list.List
	pointHighWater   int64
	pointLimit       int
	overflow         InventoryOverflow
}

func resetIEC104Store(s *iec104Store) {
	s.pairs = newBounded[pairKey, *pairState](MaxIEC104Pairs)
	s.pairs.onRemove = func(_ pairKey, pair *pairState, evicted bool) {
		pair.cas.removeAll(evicted)
	}
	s.pointEntries = make(map[iecPointRef]*list.Element)
	s.pointOrder.Init()
	s.pointHighWater = 0
	s.pointLimit = limits.MaxInventoryPoints
	s.overflow = InventoryOverflow{}
	s.busyObservations.Store(0)
}

// ObserveIEC104 must be called outside the engine's IEC table lock. It must stay
// cheap and non-blocking: no I/O, external callbacks or channel waits. It uses
// its own TryLock; contention drops the observation and increments
// overflow.observations. All work is bounded. Call once per deduplicated APDU,
// with no delivery-outcome tracking.
// Only control-direction command type IDs count as attempts. Inventory
// is observational and never feeds the learner or auto-ALLOW.
func (inv *Inventory) ObserveIEC104(o IEC104Observation) {
	if !o.Controlling.IsValid() || !o.Controlled.IsValid() {
		return
	}
	s := &inv.iec104
	if !s.mu.TryLock() {
		s.busyObservations.Add(1)
		return
	}
	defer s.mu.Unlock()
	now := time.Now()
	at := o.Time
	if at.IsZero() {
		at = now.UTC()
	}
	pKey := pairKey{o.Controlling, o.Controlled}
	p := s.pairs.observe(pKey, now, func() *pairState {
		pair := &pairState{
			IEC104Pair: IEC104Pair{Controlling: o.Controlling, Controlled: o.Controlled, FirstSeen: at, LastSeen: at},
			cas:        newBounded[uint16, *caState](MaxIEC104CAs),
		}
		pair.cas.onRemove = func(_ uint16, ca *caState, evicted bool) {
			ca.points.removeAll(evicted)
		}
		return pair
	}, &s.overflow.Pairs)
	seen(&p.FirstSeen, &p.LastSeen, at)
	ca := p.cas.observe(o.CA, now, func() *caState {
		ca := &caState{
			IEC104CA: IEC104CA{CA: o.CA, FirstSeen: at, LastSeen: at},
			points:   newBounded[pointKey, *IEC104Point](MaxIEC104Points),
		}
		ca.points.onRemove = func(key pointKey, _ *IEC104Point, evicted bool) {
			s.removePointLocked(iecPointRef{pair: pKey, ca: o.CA, point: key}, evicted, inv)
		}
		return ca
	}, &s.overflow.CAs)
	seen(&ca.FirstSeen, &ca.LastSeen, at)
	if o.IsCommand() {
		p.AttemptedCommands++
		ca.AttemptedCommands++
	}
	// One ASDU has at most 127 information objects. Keep input work bounded too.
	ioas := o.IOAs
	if len(ioas) > 127 {
		s.overflow.Points += uint64(len(ioas) - 127)
		ioas = ioas[:127]
	}
	for _, ioa := range ioas {
		if ioa > 0xffffff {
			s.overflow.Points++
			continue
		}
		key := pointKey{ioa, o.TypeID}
		ref := iecPointRef{pair: pKey, ca: o.CA, point: key}
		ca.points.expire(now)
		_, exists := ca.points.items[key]
		pointLimit := s.pointLimit
		if pointLimit <= 0 {
			pointLimit = limits.MaxInventoryPoints
		}
		if !exists && len(s.pointEntries) >= pointLimit {
			s.evictOldestPointLocked(inv)
		}
		var localEvictions uint64
		point := ca.points.observe(key, now, func() *IEC104Point {
			return &IEC104Point{IOA: ioa, TypeID: o.TypeID, FirstSeen: at, LastSeen: at}
		}, &localEvictions)
		if exists {
			s.touchPointLocked(ref)
		} else {
			s.addPointLocked(ref)
		}
		seen(&point.FirstSeen, &point.LastSeen, at)
	}
}

func (s *iec104Store) addPointLocked(ref iecPointRef) {
	s.pointEntries[ref] = s.pointOrder.PushFront(ref)
	if int64(len(s.pointEntries)) > s.pointHighWater {
		s.pointHighWater = int64(len(s.pointEntries))
	}
}

func (s *iec104Store) touchPointLocked(ref iecPointRef) {
	if e := s.pointEntries[ref]; e != nil {
		s.pointOrder.MoveToFront(e)
	}
}

func (s *iec104Store) removePointLocked(ref iecPointRef, evicted bool, inv *Inventory) {
	if e := s.pointEntries[ref]; e != nil {
		delete(s.pointEntries, ref)
		s.pointOrder.Remove(e)
	}
	if evicted {
		s.overflow.Points++
		inv.resources.Ledger.Record(limits.TableInventoryPoints, limits.ReasonEvicted, limits.ModeObserve)
	}
}

func (s *iec104Store) evictOldestPointLocked(inv *Inventory) {
	e := s.pointOrder.Back()
	if e == nil {
		return
	}
	ref := e.Value.(iecPointRef)
	pairElement := s.pairs.items[ref.pair]
	if pairElement != nil {
		pair := pairElement.Value.(*entry[pairKey, *pairState]).value
		caElement := pair.cas.items[ref.ca]
		if caElement != nil {
			ca := caElement.Value.(*entry[uint16, *caState]).value
			if ca.points.remove(ref.point, true) {
				return
			}
		}
	}
	// Keep the global index self-healing if a hierarchy row was already absent.
	s.removePointLocked(ref, false, inv)
}

func commandType(t uint8) bool { return (t >= 45 && t <= 51) || (t >= 58 && t <= 64) }
func seen(first, last *time.Time, at time.Time) {
	if at.Before(*first) {
		*first = at
	}
	if at.After(*last) {
		*last = at
	}
}

// SnapshotIEC104 returns a detached, deterministically sorted view. Reads do not
// extend retention. Overflow totals survive evictions and reset only on Clear.
func (inv *Inventory) SnapshotIEC104() IEC104Snapshot {
	s := &inv.iec104
	s.mu.Lock()
	now := time.Now()
	s.pairs.expire(now)
	out := IEC104Snapshot{Pairs: make([]IEC104Pair, 0, len(s.pairs.items)), Overflow: s.overflow,
		Limits: InventoryLimits{MaxIEC104Pairs, MaxIEC104CAs, MaxIEC104Points, MaxAssets, MaxPeers, MaxStationAddresses, int(MaxIdle.Seconds())}}
	for _, e := range s.pairs.items {
		p := e.Value.(*entry[pairKey, *pairState]).value
		cp := p.IEC104Pair
		cp.CAs = make([]IEC104CA, 0)
		p.cas.expire(now)
		for _, e := range p.cas.items {
			ca := e.Value.(*entry[uint16, *caState]).value
			cc := ca.IEC104CA
			cc.Points = make([]IEC104Point, 0)
			ca.points.expire(now)
			for _, e := range ca.points.items {
				cc.Points = append(cc.Points, *e.Value.(*entry[pointKey, *IEC104Point]).value)
			}
			cp.CAs = append(cp.CAs, cc)
		}
		out.Pairs = append(out.Pairs, cp)
	}
	out.Overflow.Observations = s.busyObservations.Load()
	s.mu.Unlock()
	for i := range out.Pairs {
		cas := out.Pairs[i].CAs
		sort.Slice(cas, func(i, j int) bool { return cas[i].CA < cas[j].CA })
		for j := range cas {
			points := cas[j].Points
			sort.Slice(points, func(i, j int) bool {
				if points[i].IOA == points[j].IOA {
					return points[i].TypeID < points[j].TypeID
				}
				return points[i].IOA < points[j].IOA
			})
		}
	}

	sort.Slice(out.Pairs, func(i, j int) bool {
		if out.Pairs[i].Controlling == out.Pairs[j].Controlling {
			return out.Pairs[i].Controlled.Compare(out.Pairs[j].Controlled) < 0
		}
		return out.Pairs[i].Controlling.Compare(out.Pairs[j].Controlling) < 0
	})
	inv.mu.RLock()
	out.Overflow.Assets = inv.overflow.Assets
	out.Overflow.Peers = inv.overflow.Peers
	out.Overflow.StationAddresses = inv.overflow.StationAddresses
	inv.mu.RUnlock()
	return out
}
