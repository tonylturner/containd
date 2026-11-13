// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type rulesEpoch uint64
type pairReason string

const (
	pairOK             pairReason = "paired"
	pairUnpaired       pairReason = "unpaired"
	pairExpired        pairReason = "pairing_expired"
	pairAmbiguous      pairReason = "pairing_ambiguous"
	pairUnsupported    pairReason = "pairing_unsupported"
	pairUnknown        pairReason = "pairing_unknown"
	pairMismatch       pairReason = "pairing_mismatch"
	autonomousRequired pairReason = "autonomous_rule_required"
	sessionRequired    pairReason = "session_rule_required"
	messageTimeout     pairReason = "message_timeout"
	stateLimit         pairReason = "state_limit"
)
const pairSessionCap = 64
const pairGlobalCap = 16384

type protocolPairKey interface{ comparable }
type pairProgress struct {
	Phase, ExpectedSequence uint8
	Fragments               uint16
}
type requestPermit struct {
	Epoch    rulesEpoch
	Contexts []rules.EvalContext
}
type pairGrant[K protocolPairKey, S any] struct {
	Key              K
	Request          S
	Permit           requestPermit
	Observe          bool
	Created, Expires time.Time
	State            pairProgress
	lease            *limits.Lease
	contextLease     *limits.Lease
	autonomous       bool
}
type pairMarker[K protocolPairKey] struct {
	key    K
	reason pairReason
}
type pairAdapter[K protocolPairKey, S any] interface {
	Classify(dpi.DecodedFrame, dpi.StreamDir) (rules.MessageClass, K, S, pairReason)
	Matches(K, K) bool
	Conflicts(K, K) bool
	Advance(S, pairProgress, S) (pairProgress, bool, pairReason)
	Lifetime(S) time.Duration
	Grants(S) bool
	Charge(S) int64
	Copy(S) S
}
type sessionPairing interface {
	inspect(dpi.DecodedFrame, dpi.StreamDir, time.Time) (rules.MessageClass, pairReason)
	apply(dpi.DecodedFrame, dpi.StreamDir, requestPermit, time.Time) pairReason
	expire(time.Time)
	reauthorize(*compiledRules, rules.EvalContext, time.Time) pairReason
	close()
}
type pairLedger[K protocolPairKey, S any] struct {
	adapter     pairAdapter[K, S]
	resources   limits.Resources
	observe     bool
	total       *int
	grants      []*pairGrant[K, S]
	markers     []pairMarker[K]
	markerLease *limits.Lease
}

func newPairing(proto string, r limits.Resources, observe bool, total *int) sessionPairing {
	switch proto {
	case "modbus":
		return &pairLedger[modbusPairKey, modbus.PairShape]{adapter: modbusPairAdapter{}, resources: r, observe: observe, total: total}
	case "dnp3":
		return &pairLedger[dnp3PairKey, dnp3.PairShape]{adapter: dnp3PairAdapter{}, resources: r, observe: observe, total: total}
	case "iec104":
		return &pairLedger[iecPairKey, iec104.PairShape]{adapter: iecPairAdapter{}, resources: r, observe: observe, total: total}
	default:
		return nil
	}
}
func (b *pairLedger[K, S]) class() limits.Class {
	if b.observe {
		return limits.ClassObserve
	}
	return limits.ClassEnforce
}
func (b *pairLedger[K, S]) inspect(f dpi.DecodedFrame, dir dpi.StreamDir, now time.Time) (rules.MessageClass, pairReason) {
	b.expire(now)
	class, k, s, reason := b.adapter.Classify(f, dir)
	if reason != pairOK {
		return class, reason
	}
	if class != rules.ClassSolicited {
		return class, pairOK
	}
	_, _, _, reason = b.reply(k, s)
	return class, reason
}
func (b *pairLedger[K, S]) reply(k K, s S) (int, pairProgress, bool, pairReason) {
	found := -1
	var next pairProgress
	var terminal bool
	for i, g := range b.grants {
		if !g.autonomous && b.adapter.Matches(g.Key, k) {
			if found >= 0 {
				return -1, next, false, pairAmbiguous
			}
			found = i
			var reason pairReason
			next, terminal, reason = b.adapter.Advance(g.Request, g.State, s)
			if reason != pairOK {
				return -1, next, false, reason
			}
		}
	}
	if found >= 0 {
		return found, next, terminal, pairOK
	}
	for i := len(b.markers) - 1; i >= 0; i-- {
		if b.adapter.Matches(b.markers[i].key, k) {
			return -1, next, false, b.markers[i].reason
		}
	}
	return -1, next, false, pairUnpaired
}
func (b *pairLedger[K, S]) apply(f dpi.DecodedFrame, dir dpi.StreamDir, permit requestPermit, now time.Time) pairReason {
	b.expire(now)
	class, k, s, reason := b.adapter.Classify(f, dir)
	if reason != pairOK {
		return reason
	}
	switch class {
	case rules.ClassRequest:
		if !b.adapter.Grants(s) {
			return pairOK
		}
		// Reuse is ambiguous even when a peer changes FC while retaining TID.
		for i := len(b.grants) - 1; i >= 0; i-- {
			if b.adapter.Conflicts(b.grants[i].Key, k) {
				b.mark(b.grants[i].Key, pairAmbiguous)
				b.remove(i)
				b.mark(k, pairAmbiguous)
				return pairAmbiguous
			}
		}
		return b.add(k, s, permit, now)
	case rules.ClassSolicited:
		i, next, terminal, why := b.reply(k, s)
		if why != pairOK {
			return why
		}
		if terminal {
			b.remove(i)
		} else {
			b.grants[i].State = next
		}
		return pairOK
	case rules.ClassAutonomous:
		return b.autonomous(k, s, now)
	default:
		return pairOK
	}
}
func (b *pairLedger[K, S]) add(k K, s S, permit requestPermit, now time.Time) pairReason {
	if b.markerLease == nil {
		lease, ok := b.resources.Budget.Reserve(b.class(), limits.CategoryPairing, pairSessionCap*limits.PairingMetadataBytes)
		if !ok {
			return stateLimit
		}
		b.markerLease = lease
		b.markers = make([]pairMarker[K], 0, pairSessionCap)
		b.grants = make([]*pairGrant[K, S], 0, pairSessionCap)
	}
	n := limits.PairingMetadataBytes + b.adapter.Charge(s) + pairContextsCharge(permit.Contexts)
	lease, ok := b.resources.Budget.Reserve(b.class(), limits.CategoryPairing, n)
	if !ok {
		return stateLimit
	}
	if b.total != nil && *b.total >= pairGlobalCap && len(b.grants) < pairSessionCap {
		lease.Release()
		return stateLimit
	}
	if len(b.grants) == pairSessionCap {
		// Insertion order is the deterministic tie-break for equal Created.
		oldest := 0
		for i, g := range b.grants {
			if g.Created.Before(b.grants[oldest].Created) {
				oldest = i
			}
		}
		b.mark(b.grants[oldest].Key, pairExpired)
		b.remove(oldest)
		b.resources.Ledger.Record(limits.TableInspection, limits.ReasonEvicted, limits.Mode(b.mode()))
	}
	g := &pairGrant[K, S]{Key: k, Request: b.adapter.Copy(s), Permit: requestPermit{Epoch: permit.Epoch, Contexts: pairCopyContexts(permit.Contexts)},
		Observe: b.observe, Created: now, Expires: now.Add(b.adapter.Lifetime(s)), lease: lease}
	if q, ok := any(s).(dnp3.PairShape); ok {
		g.State.ExpectedSequence = q.Sequence
	}
	b.grants = append(b.grants, g)
	if b.total != nil {
		*b.total++
	}
	return pairOK
}
func (b *pairLedger[K, S]) autonomous(k K, s S, now time.Time) pairReason {
	r, ok := any(s).(dnp3.PairShape)
	if !ok {
		return pairOK
	}
	for i, g := range b.grants {
		if !g.autonomous || !b.adapter.Matches(g.Key, k) {
			continue
		}
		if r.FIR || r.Sequence != g.State.ExpectedSequence {
			return pairMismatch
		}
		if r.FIN {
			b.remove(i)
		} else {
			g.State.ExpectedSequence = (r.Sequence + 1) & 15
			g.State.Fragments++
		}
		return pairOK
	}
	if !r.FIR {
		return pairUnpaired
	}
	if r.FIN {
		return pairOK
	}
	if reason := b.add(k, s, requestPermit{}, now); reason != pairOK {
		return reason
	}
	g := b.grants[len(b.grants)-1]
	g.autonomous = true
	g.State.ExpectedSequence = (r.Sequence + 1) & 15
	g.State.Fragments = 1
	return pairOK
}
func (b *pairLedger[K, S]) remove(i int) {
	b.grants[i].lease.Release()
	if b.grants[i].contextLease != nil {
		b.grants[i].contextLease.Release()
	}
	copy(b.grants[i:], b.grants[i+1:])
	b.grants[len(b.grants)-1] = nil
	b.grants = b.grants[:len(b.grants)-1]
	if b.total != nil {
		*b.total--
	}
}
func (b *pairLedger[K, S]) mark(k K, reason pairReason) {
	if len(b.markers) == pairSessionCap {
		copy(b.markers, b.markers[1:])
		b.markers = b.markers[:pairSessionCap-1]
	}
	b.markers = append(b.markers, pairMarker[K]{k, reason})
}
func (b *pairLedger[K, S]) mode() string {
	if b.observe {
		return "monitor"
	}
	return "enforce"
}
func (b *pairLedger[K, S]) expire(now time.Time) {
	for i := len(b.grants) - 1; i >= 0; i-- {
		if !now.Before(b.grants[i].Expires) {
			b.mark(b.grants[i].Key, pairExpired)
			b.remove(i)
		}
	}
}
func (b *pairLedger[K, S]) close() {
	for len(b.grants) > 0 {
		b.remove(len(b.grants) - 1)
	}
	if b.markerLease != nil {
		b.markerLease.Release()
		b.markerLease = nil
	}
	b.markers = nil
	b.grants = nil
}
func pairCopyPtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func pairEqualPtr[T comparable](a, b *T) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
