// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

func TestReconfigureWaitsForNFLogStopBeforeNextBind(t *testing.T) {
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	var mu sync.Mutex
	var bound bool
	var overlap bool
	var binds, stops int
	startNFLog = func(context.Context, uint16, capture.RuleHitSink, func(error)) (func(), error) {
		mu.Lock()
		if bound {
			overlap = true
		}
		bound = true
		binds++
		mu.Unlock()

		return func() {
			time.Sleep(time.Millisecond)
			mu.Lock()
			bound = false
			stops++
			mu.Unlock()
		}, nil
	}

	newEngine := func() *Engine {
		e, err := New(Config{NFLogGroup: 100})
		if err != nil {
			t.Fatalf("create engine: %v", err)
		}
		return e
	}
	e := newEngine()
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("initial Start: %v", err)
	}

	const reconfigures = 100
	for i := 0; i < reconfigures; i++ {
		e.Reconfigure(newEngine())
		if err := e.Start(context.Background()); err != nil {
			t.Fatalf("Start after reconfigure %d: %v", i, err)
		}
	}
	// Disable nflog and verify the last consumer's stop also completes.
	e.Reconfigure(newEngineWithoutNFLog(t))

	mu.Lock()
	gotOverlap, gotBinds, gotStops := overlap, binds, stops
	mu.Unlock()
	if gotOverlap {
		t.Fatal("new nflog bind began before the previous stop completed")
	}
	if gotBinds != reconfigures+1 || gotStops != gotBinds {
		t.Fatalf("bind/stop totals = %d/%d, want %d/%d", gotBinds, gotStops, reconfigures+1, reconfigures+1)
	}
	for _, event := range e.Events().List(100) {
		if event.Kind == "service.nflog.unavailable" {
			t.Fatalf("unexpected nflog unavailable event: %+v", event)
		}
	}
}

func newEngineWithoutNFLog(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("create engine without nflog: %v", err)
	}
	return e
}

func TestStartNFLogErrorIsReportedAndStored(t *testing.T) {
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	wantErr := errors.New("permission denied")
	startNFLog = func(context.Context, uint16, capture.RuleHitSink, func(error)) (func(), error) {
		return func() {}, wantErr
	}

	var reported error
	e, err := New(Config{
		NFLogGroup: 100,
		OnError:    func(err error) { reported = err },
	})
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start should keep nflog failure non-fatal: %v", err)
	}
	if reported == nil || !errors.Is(reported, wantErr) {
		t.Fatalf("OnError = %v, want wrapped %v", reported, wantErr)
	}
	events := e.Events().List(10)
	if len(events) != 1 || events[0].Kind != "service.nflog.unavailable" {
		t.Fatalf("events = %+v, want one service.nflog.unavailable event", events)
	}
	if got, want := events[0].Attributes["error"], wantErr.Error(); got != want {
		t.Fatalf("unavailable error = %v, want %q", got, want)
	}
	if got, want := reported.Error(), fmt.Sprintf("nflog group 100 unavailable: %v", wantErr); got != want {
		t.Fatalf("reported error = %q, want %q", got, want)
	}
}
