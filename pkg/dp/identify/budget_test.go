// SPDX-License-Identifier: Apache-2.0
package identify

import (
	"testing"
	"time"
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func releaseReplayAfterTest(t *testing.T, r Replay) {
	t.Helper()
	t.Cleanup(r.Release)
}

func TestInspectionMetadataChargeCoversEntry(t *testing.T) {
	if n := int64(unsafe.Sizeof(entry{})); n > limits.DecoderMetadataBytes {
		t.Fatalf("fixed entry credit %d does not cover metadata %d", limits.DecoderMetadataBytes, n)
	}
	if int64(EntryCharge) > 2*limits.DecoderMetadataBytes {
		t.Fatal("legacy table accounting exceeds the live budget conversion")
	}
}

func TestInspectionBudgetAdmissionAndPrefix(t *testing.T) {
	for _, capacity := range []int64{1, 4096} {
		r := limits.NewResources(limits.NewBudget(capacity), nil)
		table, err := NewTable(DefaultBudgets(), time.Now, r)
		if err != nil {
			t.Fatal(err)
		}
		ok := table.Open(testKey, Meta{Transport: 6})
		if capacity == 1 {
			if ok {
				t.Fatal("admitted uncharged metadata")
			}
		} else {
			if !ok {
				t.Fatal("metadata admission")
			}
			observe(t, table, Arrival{SYN: true, Sequence: 99})
			observe(t, table, Arrival{Direction: 1, SYN: true, Sequence: 199})
			observe(t, table, Arrival{Sequence: 100, Payload: []byte{0x68}})
			d := observe(t, table, Arrival{Direction: 1, Sequence: 200, Payload: []byte{0x68}})
			if !d.InspectionRefused || d.State != Incomplete {
				t.Fatalf("prefix admission = %+v", d)
			}
			observe(t, table, Arrival{Payload: []byte{0x68}})
		}
		hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
		if len(hits) != 1 || hits[0].Mode != limits.ModeMonitor || hits[0].Total != 1 {
			t.Fatal(hits)
		}
		table.Release(testKey)
		if r.Budget.Status().InUse != 0 {
			t.Fatal("teardown leaked")
		}
	}
}

func TestInspectionReplayRetainsCreditUntilRelease(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(16384), nil)
	table, err := NewTable(DefaultBudgets(), time.Now, r)
	if err != nil {
		t.Fatal(err)
	}
	if !table.Open(testKey, Meta{Transport: 6}) {
		t.Fatal("admission")
	}
	observe(t, table, Arrival{SYN: true, Sequence: 99})
	observe(t, table, Arrival{Direction: 1, SYN: true, Sequence: 199})
	complete(t, table, fixtures()[0])
	_, replay, ok := table.Take(testKey)
	if !ok {
		t.Fatal("take")
	}
	table.Release(testKey)
	if r.Budget.Status().InUse == 0 {
		t.Fatal("replay backing was refunded while still retained")
	}
	replay.Release()
	replay.Release()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("replay leaked credit")
	}
}

func TestInspectionPendingReplayAdmission(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(16384), nil)
	table, err := NewTable(DefaultBudgets(), time.Now, r)
	if err != nil {
		t.Fatal(err)
	}
	table.Open(testKey, Meta{Transport: 6})
	observe(t, table, Arrival{SYN: true, Sequence: 99})
	observe(t, table, Arrival{Direction: 1, SYN: true, Sequence: 199})
	observe(t, table, Arrival{Sequence: 120, Payload: []byte("pending")})
	complete(t, table, fixtures()[0])
	used := r.Budget.Status().InUse
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 16384-used)
	if !ok {
		t.Fatal("blocker")
	}
	d, replay, ok := table.Take(testKey)
	if !ok || d.State != Incomplete || !d.InspectionRefused || len(replay.Bytes[0]) != 0 || len(replay.Pending[0]) != 0 {
		t.Fatal("published uncharged pending replay", d, replay)
	}
	replay.Release()
	blocker.Release()
	table.Release(testKey)
	if r.Budget.Status().InUse != 0 {
		t.Fatal("failed replay leaked")
	}
}

func TestInspectionAdoptionAllocationRefusal(t *testing.T) {
	for _, path := range []string{"key", "prefix"} {
		t.Run(path, func(t *testing.T) {
			r := limits.NewResources(limits.NewBudget(32768), nil)
			table, err := NewTable(DefaultBudgets(), time.Now, r)
			if err != nil {
				t.Fatal(err)
			}
			table.Open("a", Meta{Transport: 6})
			to := Key("longer")
			if path == "prefix" {
				to = "b"
				table.Open(to, Meta{Transport: 6})
				table.Observe("a", Arrival{SYN: true, Sequence: 99, Payload: []byte{0}})
				table.Observe(to, Arrival{SYN: true, Sequence: 99})
			}
			blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 32768-r.Budget.Status().InUse)
			if !ok {
				t.Fatal("blocker")
			}
			result, ok := table.Adopt("a", to, Remap{0, 1})
			if !ok || !result.InspectionRefused {
				t.Fatal("adoption bypassed allocation admission", result)
			}
			blocker.Release()
			table.Release("a")
			table.Release(to)
			if r.Budget.Status().InUse != 0 {
				t.Fatal("adoption leaked")
			}
			hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Total != 1 {
				t.Fatal(hits)
			}
		})
	}
}
