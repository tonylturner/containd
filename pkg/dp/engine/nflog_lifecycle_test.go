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
	"github.com/tonylturner/containd/pkg/dp/events"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatalf("initial Start: %v", err)
	}

	const reconfigures = 100
	for i := 0; i < reconfigures; i++ {
		e.Reconfigure(newEngine())
		if err := e.Start(ctx); err != nil {
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

func TestConcurrentReconfigureAndStartSerializeNFLogLifecycle(t *testing.T) {
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	const commits = 100
	freshEngines := make([]*Engine, commits)
	for i := range freshEngines {
		freshEngines[i] = newEngineWithNFLog(t)
	}
	e := newEngineWithoutNFLog(t)

	var mu sync.Mutex
	var bound bool
	var overlap bool
	var bindAttempts int
	var eventStores []*events.Store
	var stopFns []func()
	firstBindEntered := make(chan struct{})
	releaseFirstBind := make(chan struct{})
	startNFLog = func(_ context.Context, _ uint16, sink capture.RuleHitSink, _ func(error)) (func(), error) {
		store, ok := sink.(*events.Store)
		if !ok {
			return func() {}, errors.New("unexpected NFLOG sink type")
		}

		mu.Lock()
		eventStores = append(eventStores, store)
		bindAttempts++
		firstBind := bindAttempts == 1
		if bound {
			overlap = true
			mu.Unlock()
			return func() {}, errors.New("simulated EPERM: previous consumer still owns the group")
		}
		bound = true
		mu.Unlock()

		if firstBind {
			close(firstBindEntered)
			<-releaseFirstBind
		}
		time.Sleep(time.Millisecond)

		var once sync.Once
		stop := func() {
			once.Do(func() {
				time.Sleep(time.Millisecond)
				mu.Lock()
				bound = false
				mu.Unlock()
			})
		}
		mu.Lock()
		stopFns = append(stopFns, stop)
		mu.Unlock()
		return stop, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var starts sync.WaitGroup
	startErrors := make(chan error, commits)
	for i, fresh := range freshEngines {
		e.Reconfigure(fresh)
		starts.Add(1)
		go func() {
			defer starts.Done()
			if err := e.Start(ctx); err != nil {
				startErrors <- err
			}
		}()
		if i == 0 {
			// Ensure commit 2 reaches Reconfigure while Start 1 is still
			// inside the fake bind. The timer releases the fake shortly after;
			// the commit loop itself has no sleeps between iterations.
			<-firstBindEntered
			time.AfterFunc(5*time.Millisecond, func() { close(releaseFirstBind) })
		}
	}
	starts.Wait()
	close(startErrors)
	for err := range startErrors {
		t.Errorf("Start returned error: %v", err)
	}

	// The last config disables NFLOG, so Reconfigure must stop whichever
	// consumer started last before returning.
	e.Reconfigure(newEngineWithoutNFLog(t))

	mu.Lock()
	gotOverlap := overlap
	stores := append([]*events.Store(nil), eventStores...)
	stops := append([]func(){}, stopFns...)
	mu.Unlock()
	for _, stop := range stops {
		stop() // Cleanup remains idempotent if a failure path did not retain one.
	}
	if gotOverlap {
		t.Fatal("a bind overlapped the previous NFLOG consumer")
	}
	for _, store := range stores {
		for _, event := range store.List(1000) {
			if event.Kind == "service.nflog.unavailable" {
				t.Fatalf("unexpected nflog unavailable event: %+v", event)
			}
		}
	}
}

func newEngineWithNFLog(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{NFLogGroup: 100})
	if err != nil {
		t.Fatalf("create engine with nflog: %v", err)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, err := New(Config{
		NFLogGroup: 100,
		OnError:    func(err error) { reported = err },
	})
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	if err := e.Start(ctx); err != nil {
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
