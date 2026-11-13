// SPDX-License-Identifier: Apache-2.0
package observe

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestObservationInspectionMetadataAdmission(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(1), nil)
	o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
	if o.Open("refused", identify.Meta{Transport: 6}) {
		t.Fatal("admitted uncharged observer metadata")
	}
	if r.Budget.Status().InUse != 0 || o.Counters().Markers != 0 || o.Counters().Entries != 0 {
		t.Fatal("admission rollback leaked")
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Total != 1 {
		t.Fatal(hits)
	}
}

func TestObservationInspectionReplacementAndSessionRefusal(t *testing.T) {
	for _, path := range []string{"replacement", "session"} {
		t.Run(path, func(t *testing.T) {
			r := limits.NewResources(limits.NewBudget(65536), nil)
			o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
			key := identify.Key(strings.Repeat("k", 512))
			states := openTCP(t, o, key)
			data := request[:4]
			if path == "session" {
				data = request
			}
			payload(o, key, states, 0, 100, data)
			room := 2*int64(unsafe.Sizeof(stamp{})) - 1
			if path == "session" {
				_, localBytes := o.table.Usage()
				prefixCost := localBytes - identify.EntryCharge
				room = int64(prefixCost) + int64(unsafe.Sizeof(stamp{}))
			}
			blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 65536*3/4-r.Budget.Status().InUse-room)
			if !ok {
				t.Fatal("blocker")
			}
			var out Output
			if path == "session" {
				out = payload(o, key, states, 1, 200, reply)
			} else {
				out = payload(o, key, states, 0, 104, request[4:])
			}
			if len(out.Batches) != 1 || len(out.Batches[0].Events) != 0 {
				t.Fatalf("missing loss or published refused replay: %+v", out)
			}
			var se *dpi.StreamError
			if !errors.As(out.Batches[0].Err, &se) || se.Kind != dpi.StreamStateLimit {
				t.Fatal(out)
			}
			blocker.Release()
			o.Release(key)
			if r.Budget.Status().InUse != 0 {
				t.Fatal("teardown leaked")
			}
			hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Total != 1 {
				t.Fatal(hits)
			}
		})
	}
}

func TestObservationInspectionAdoptionRefusal(t *testing.T) {
	for _, path := range []string{"key", "stamps"} {
		t.Run(path, func(t *testing.T) {
			r := limits.NewResources(limits.NewBudget(65536), nil)
			o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
			a := openTCP(t, o, "a")
			payload(o, "a", a, 0, 100, request[:4])
			room := int64(0)
			if path == "stamps" {
				b := openTCP(t, o, "b")
				payload(o, "b", b, 0, 104, request[4:])
				room = 2*int64(unsafe.Sizeof(stamp{})) - 1
			}
			blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 65536*3/4-r.Budget.Status().InUse-room)
			if !ok {
				t.Fatal("blocker")
			}
			out := o.Adopt("a", "b", identify.Remap{0, 1})
			want := 1
			if path == "stamps" {
				want = 2 // both pending incarnations become terminal losses
			}
			if len(out.Batches) != want {
				t.Fatalf("adoption losses = %+v", out)
			}
			blocker.Release()
			o.Drain()
			if r.Budget.Status().InUse != 0 {
				t.Fatal("adoption refusal leaked")
			}
			hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Total != uint64(want) {
				t.Fatal(hits)
			}
		})
	}
}

func TestObservationInspectionStampRefusal(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(32768), nil)
	o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
	states := openTCP(t, o, "k")
	used := r.Budget.Status().InUse
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 32768-used)
	if !ok {
		t.Fatal("blocker")
	}
	out := payload(o, "k", states, 0, 100, request)
	if len(out.Batches) != 1 {
		t.Fatalf("missing inspection loss: %+v", out)
	}
	var se *dpi.StreamError
	if !errors.As(out.Batches[0].Err, &se) || se.Kind != dpi.StreamStateLimit || out.Batches[0].State != states[0] {
		t.Fatal("unattributed stamp loss", out)
	}
	blocker.Release()
	for range 3 {
		if got := payload(o, "k", states, 0, 100, request); len(got.Batches) != 0 || len(got.Identifications) != 0 {
			t.Fatal("stamp-refused marker resumed")
		}
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Total != 1 {
		t.Fatal(hits)
	}
	o.Release("k")
	if r.Budget.Status().InUse != 0 {
		t.Fatal("stamp-refused teardown leaked")
	}
}

func TestObservationInspectionAdoptionRefunds(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(65536), nil)
	o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
	a, b := openTCP(t, o, "a"), openTCP(t, o, "b")
	payload(o, "a", a, 0, 100, request[:4])
	payload(o, "b", b, 0, 104, request[4:])
	o.Adopt("a", "b", identify.Remap{0, 1})
	o.Release("b")
	o.Drain()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("merged prefixes or stamps leaked")
	}
}

func TestObservationInspectionTerminalLossSurvivesAdoption(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(65536), nil)
	o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
	t.Cleanup(func() { o.Drain() })
	a := openTCP(t, o, "clean")
	payload(o, "clean", a, 0, 100, request)
	payload(o, "clean", a, 1, 200, reply)
	b := openTCP(t, o, "lost")
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 65536-r.Budget.Status().InUse)
	if !ok {
		t.Fatal("blocker")
	}
	payload(o, "lost", b, 0, 100, request)
	blocker.Release()
	o.Adopt("clean", "lost", identify.Remap{0, 1})
	status, ok := o.Lookup("lost")
	if !ok || status.Binding != None || status.Coverage != identify.Truncated {
		t.Fatal("adoption erased an admitted incarnation's terminal loss", status)
	}
	if out := payload(o, "lost", a, 0, 112, request); len(out.Batches) != 0 {
		t.Fatal("adopted loss resumed decoding")
	}
	o.Drain()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("adopted terminal loss leaked")
	}
}

func TestObservationInspectionRefusedTerminalRekey(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(65536), nil)
	o, _ := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
	t.Cleanup(func() { o.Drain() })
	a := openTCP(t, o, "lost")
	block := func() *limits.Lease {
		lease, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 65536-r.Budget.Status().InUse)
		if !ok {
			t.Fatal("blocker")
		}
		return lease
	}
	blocker := block()
	payload(o, "lost", a, 0, 100, request)
	blocker.Release()
	b := openTCP(t, o, "clean")
	payload(o, "clean", b, 0, 100, request)
	payload(o, "clean", b, 1, 200, reply)
	blocker = block()
	o.Adopt("lost", "clean", identify.Remap{0, 1})
	blocker.Release()
	status, ok := o.Lookup("clean")
	if !ok || status.Binding != None || status.Coverage != identify.Truncated {
		t.Fatal("refused rekey erased the source's terminal loss", status)
	}
	o.Drain()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("refused terminal rekey leaked")
	}
}
