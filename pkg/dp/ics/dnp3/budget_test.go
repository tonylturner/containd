// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func budgetDecoder(t *testing.T, n int64) (*Decoder, limits.Resources) {
	t.Helper()
	d := NewDecoder()
	r := limits.NewResources(limits.NewBudget(n), nil)
	setter, ok := any(d).(interface{ SetResources(limits.Resources) })
	if !ok {
		t.Fatal("decoder does not accept shared inspection resources")
	}
	setter.SetResources(r)
	return d, r
}

func TestDNP3BudgetAdmissionAndRefund(t *testing.T) {
	d, r := budgetDecoder(t, 8192)
	parseAssembly(t, d, "s", dpi.ClientToServer, linkFrame(0x44, []byte{TransportFIR, 1}))
	if got := r.Budget.Status(); got.InUse <= int64(contextCharge) || got.InUse > got.Limit/4 {
		t.Fatalf("uncharged context or assembly: %+v", got)
	}
	d.StreamEnded("s", dpi.ClientToServer)
	d.StreamEnded("s", dpi.ClientToServer)
	if got := r.Budget.Status().InUse; got != 0 {
		t.Fatalf("leaked or double-refunded %d bytes", got)
	}
}

func TestDNP3LocalBudgetFinding(t *testing.T) {
	d, r := budgetDecoder(t, 4096)
	events := parseAssembly(t, d, "s", dpi.ClientToServer, linkFrame(0x44, []byte{TransportFIR, 1}))
	hasCode(t, expectOne(t, events), "undecoded", "dnp3.assembly_budget")
	if len(d.stations) != 0 || r.Budget.Status().InUse != 0 {
		t.Fatal("refused context was retained")
	}
}

func TestDNP3MixedClassBudget(t *testing.T) {
	d, r := budgetDecoder(t, 16384)
	wire := linkFrame(0x44, []byte{TransportFIR, 1})
	parseAssembly(t, d, "monitor", dpi.ClientToServer, wire)
	observe := d.leases[limits.ClassObserve].Size()
	// A shared budget can cross the observation ceiling while this decoder
	// still has local headroom. New enforcement must use a different lease.
	external, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryStream, 12000)
	if !ok {
		t.Fatal("external reservation")
	}
	res, err := d.ParseStream(dnp3State(), dpi.StreamView{
		Session: "enforce", Dir: dpi.ClientToServer, Bytes: wire, Enforcing: true,
	})
	if err != nil || res.Consumed != len(wire) {
		t.Fatalf("monitor lease starved enforcement: %+v %v", res, err)
	}
	if d.leases[limits.ClassObserve].Size() != observe || d.leases[limits.ClassEnforce] == nil {
		t.Fatal("retained bytes were reclassified")
	}
	// Changing a call's flag cannot reclassify an admitted station.
	_, err = d.ParseStream(dnp3State(), dpi.StreamView{
		Session: "monitor", Dir: dpi.ClientToServer,
		Bytes: linkFrame(0x44, []byte{1, 2}), Enforcing: true,
	})
	var se *dpi.StreamError
	if !errors.As(err, &se) || se.Kind != dpi.StreamStateLimit {
		t.Fatalf("monitor growth bypassed its ceiling: %v", err)
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Mode != limits.ModeMonitor || hits[0].Total != 1 {
		t.Fatalf("wrong refusal attribution: %+v", hits)
	}
	d.StreamEnded("monitor", dpi.ClientToServer)
	d.StreamEnded("enforce", dpi.ClientToServer)
	external.Release()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("leaked class credit")
	}
}

func TestDNP3GlobalRefusalIsTerminal(t *testing.T) {
	d, r := budgetDecoder(t, 8192)
	wire := linkFrame(0x44, []byte{TransportFIR, 1})
	parseAssembly(t, d, "s", dpi.ClientToServer, wire)
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 8192-r.Budget.Status().InUse)
	if !ok {
		t.Fatal("external reservation")
	}
	view := dpi.StreamView{Session: "s", Dir: dpi.ClientToServer, Bytes: linkFrame(0x44, []byte{1, 2})}
	_, err := d.ParseStream(dnp3State(), view)
	var se *dpi.StreamError
	if !errors.As(err, &se) || se.Kind != dpi.StreamStateLimit {
		t.Fatalf("global refusal did not propagate: %v", err)
	}
	blocker.Release()
	_, nextErr := d.ParseStream(dnp3State(), view)
	if nextErr != err {
		t.Fatal("failed incarnation resumed")
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Total != 1 {
		t.Fatalf("repeated transition: %+v", hits)
	}
	d.StreamEnded("s", dpi.ClientToServer)
	if r.Budget.Status().InUse != 0 {
		t.Fatal("leaked terminal context")
	}
}

func TestDNP3BudgetGlobalAdmissionRefusal(t *testing.T) {
	d, r := budgetDecoder(t, 8192)
	blocker, _ := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 6000)
	res, err := d.ParseStream(dnp3State(), dpi.StreamView{
		Session: "s", Bytes: linkFrame(0x44, []byte{TransportFIR, 1}),
	})
	var se *dpi.StreamError
	if !errors.As(err, &se) || se.Kind != dpi.StreamStateLimit || len(res.Frames) != 0 {
		t.Fatalf("global admission refusal was a protocol finding: %+v %v", res, err)
	}
	if len(d.stations) != 0 || r.Budget.Status().InUse != 6000 {
		t.Fatal("refused station retained credit")
	}
	blocker.Release()
}

func TestDNP3BudgetRetryRefusal(t *testing.T) {
	d, r := budgetDecoder(t, 8192)
	parseAssembly(t, d, "s", dpi.ClientToServer, linkFrame(0x73, []byte{TransportFIR, 1}))
	blocker, _ := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 8192-r.Budget.Status().InUse)
	_, err := d.ParseStream(dnp3State(), dpi.StreamView{
		Session: "s", Dir: dpi.ClientToServer, Bytes: linkFrame(0x53, []byte{1, 2}),
	})
	var se *dpi.StreamError
	if !errors.As(err, &se) || se.Kind != dpi.StreamStateLimit {
		t.Fatalf("retry allocation bypassed shared credit: %v", err)
	}
	blocker.Release()
	if r.Budget.Status().InUse != int64(contextCharge+1) {
		t.Fatal("terminal station retained retry or transport bytes")
	}
	d.StreamEnded("s", dpi.ClientToServer)
	if r.Budget.Status().InUse != 0 {
		t.Fatal("terminal station leaked")
	}
}

func TestDNP3BudgetLocalReplacementPeak(t *testing.T) {
	d, r := budgetDecoder(t, 8192)
	first := append([]byte{TransportFIR}, bytes.Repeat([]byte{0}, 249)...)
	parseAssembly(t, d, "s", dpi.ClientToServer, linkFrame(0x44, first))
	// Net retained storage would fit, but replacement data, provenance and
	// retry identity must all fit while their old backings still exist.
	next := append([]byte{1}, bytes.Repeat([]byte{0}, 115)...)
	events := parseAssembly(t, d, "s", dpi.ClientToServer, linkFrame(0x44, next))
	hasCode(t, expectOne(t, events), "undecoded", "dnp3.assembly_budget")
	if hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits; len(hits) != 0 {
		t.Fatalf("local protocol bound counted as global refusal: %+v", hits)
	}
	d.StreamEnded("s", dpi.ClientToServer)
	if r.Budget.Status().InUse != 0 {
		t.Fatal("local refusal leaked storage")
	}
}
