// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
)

type nflogTestRegistration struct {
	ctx     context.Context
	source  func(capture.SourceEvent)
	stopped chan struct{}
}

func nextNFLogRegistration(t *testing.T, registrations <-chan nflogTestRegistration) nflogTestRegistration {
	t.Helper()
	select {
	case r := <-registrations:
		return r
	case <-time.After(time.Second):
		t.Fatal("NFLOG registration did not start")
		return nflogTestRegistration{}
	}
}

func TestReconfigureWaitsForNFLogStopBeforeNextBind(t *testing.T) {
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	var mu sync.Mutex
	var bound bool
	var overlap bool
	var binds, stops int
	startNFLog = func(context.Context, uint16, capture.RuleHitSink, func(error), func(capture.SourceEvent)) (func(), error) {
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

func TestRetryProtectionNFLogLifetimeIsEngineOwned(t *testing.T) {
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	registrations := make(chan nflogTestRegistration, 4)
	startNFLog = func(ctx context.Context, _ uint16, _ capture.RuleHitSink, _ func(error), _ func(capture.SourceEvent)) (func(), error) {
		r := nflogTestRegistration{ctx: ctx, stopped: make(chan struct{})}
		registrations <- r
		var once sync.Once
		return func() { once.Do(func() { close(r.stopped) }) }, nil
	}

	e := newEngineWithNFLog(t)
	t.Cleanup(e.Close)
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	if err := e.Start(lifetime); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := nextNFLogRegistration(t, registrations)

	if err := e.Reconfigure(newEngineWithNFLog(t)); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
	select {
	case <-first.stopped:
	case <-time.After(time.Second):
		t.Fatal("Reconfigure did not stop the previous NFLOG consumer")
	}

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	if err := e.RetryProtection(requestCtx); err != nil {
		cancelRequest()
		t.Fatalf("RetryProtection: %v", err)
	}
	second := nextNFLogRegistration(t, registrations)
	cancelRequest()

	select {
	case <-second.ctx.Done():
		t.Fatalf("NFLOG consumer context was cancelled with retry request: %v", second.ctx.Err())
	case <-time.After(25 * time.Millisecond):
	}
	select {
	case <-second.stopped:
		t.Fatal("NFLOG consumer stopped with retry request")
	default:
	}
	if got := protectionComponent(t, e.Protection(), "nflog").State; got != "ready" {
		t.Fatalf("NFLOG state after retry request ended = %q, want ready", got)
	}

	cancelLifetime()
	select {
	case <-second.stopped:
	case <-time.After(time.Second):
		t.Fatal("engine lifetime cancellation did not stop the NFLOG consumer")
	}
}

func TestRetryProtectionNFLogLifetimeSurvivesRetryDeadline(t *testing.T) {
	initial, maximum, attempts := startRetryInitial, startRetryMax, startRetryAttempts
	startRetryInitial, startRetryMax, startRetryAttempts = 50*time.Millisecond, 50*time.Millisecond, 2
	t.Cleanup(func() {
		startRetryInitial, startRetryMax, startRetryAttempts = initial, maximum, attempts
	})
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	registrations := make(chan nflogTestRegistration, 8)
	var calls atomic.Int32
	startNFLog = func(ctx context.Context, _ uint16, _ capture.RuleHitSink, _ func(error), _ func(capture.SourceEvent)) (func(), error) {
		r := nflogTestRegistration{ctx: ctx, stopped: make(chan struct{})}
		registrations <- r
		var once sync.Once
		stop := func() { once.Do(func() { close(r.stopped) }) }
		if calls.Add(1) <= 3 {
			return stop, errBind
		}
		return stop, nil
	}

	e := newEngineWithNFLog(t)
	t.Cleanup(e.Close)
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	if err := e.Start(lifetime); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		r := nextNFLogRegistration(t, registrations)
		select {
		case <-r.stopped:
		case <-time.After(time.Second):
			t.Fatalf("initial NFLOG attempt %d did not stop", attempt)
		}
	}
	awaitNFLogState(t, e, "failed")

	requestCtx, cancelRequest := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancelRequest()
	if err := e.RetryProtection(requestCtx); err != nil {
		t.Fatalf("RetryProtection: %v", err)
	}
	third := nextNFLogRegistration(t, registrations)
	select {
	case <-third.stopped:
	default:
		t.Fatal("failed retry bind was not stopped")
	}
	if got := protectionComponent(t, e.Protection(), "nflog").State; got != "pending" {
		t.Fatalf("NFLOG state during caller retry = %q, want pending", got)
	}
	select {
	case <-requestCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("retry request did not reach its deadline")
	}
	if got := protectionComponent(t, e.Protection(), "nflog").State; got != "pending" {
		t.Fatalf("NFLOG state after retry deadline = %q, want pending", got)
	}
	var rebound nflogTestRegistration
	select {
	case rebound = <-registrations:
	case <-time.After(time.Second):
		t.Fatal("engine-owned NFLOG retry did not bind")
	}
	awaitNFLogState(t, e, "ready")
	select {
	case <-rebound.ctx.Done():
		t.Fatalf("rebound NFLOG consumer context ended with retry deadline: %v", rebound.ctx.Err())
	default:
	}

	cancelLifetime()
	select {
	case <-rebound.stopped:
	case <-time.After(time.Second):
		t.Fatal("engine lifetime cancellation did not stop the NFLOG consumer")
	}
}

func TestRetryProtectionBeforeStartUsesDeferredEngineLifetime(t *testing.T) {
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	registrations := make(chan nflogTestRegistration, 2)
	startNFLog = func(ctx context.Context, _ uint16, _ capture.RuleHitSink, _ func(error), _ func(capture.SourceEvent)) (func(), error) {
		r := nflogTestRegistration{ctx: ctx, stopped: make(chan struct{})}
		registrations <- r
		var once sync.Once
		return func() { once.Do(func() { close(r.stopped) }) }, nil
	}

	e := newEngineWithNFLog(t)
	t.Cleanup(e.Close)
	requestCtx, cancelRequest := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelRequest()
	if err := e.RetryProtection(requestCtx); err != nil {
		t.Fatalf("RetryProtection before Start: %v", err)
	}
	select {
	case <-requestCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("retry request did not reach its deadline")
	}
	if got := protectionComponent(t, e.Protection(), "nflog").State; got != "pending" {
		t.Fatalf("NFLOG state after retry deadline = %q, want pending", got)
	}
	select {
	case <-registrations:
		t.Fatal("RetryProtection started NFLOG before an engine lifetime was known")
	default:
	}

	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	if err := e.Start(lifetime); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r := nextNFLogRegistration(t, registrations)
	select {
	case <-r.ctx.Done():
		t.Fatalf("deferred NFLOG consumer inherited request context: %v", r.ctx.Err())
	default:
	}
}

func TestUnexpectedNFLogEndReleasesOwnerForProtectionRetry(t *testing.T) {
	fastRetry(t, 2)
	oldStartNFLog := startNFLog
	t.Cleanup(func() { startNFLog = oldStartNFLog })

	registrations := make(chan nflogTestRegistration, 8)
	var calls atomic.Int32
	startNFLog = func(ctx context.Context, _ uint16, _ capture.RuleHitSink, _ func(error), source func(capture.SourceEvent)) (func(), error) {
		r := nflogTestRegistration{ctx: ctx, source: source, stopped: make(chan struct{})}
		registrations <- r
		var once sync.Once
		stop := func() { once.Do(func() { close(r.stopped) }) }
		if n := calls.Add(1); n == 2 || n == 3 {
			return stop, errBind
		}
		return stop, nil
	}

	e := newEngineWithNFLog(t)
	t.Cleanup(e.Close)
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	if err := e.Start(lifetime); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := nextNFLogRegistration(t, registrations)
	first.source(capture.SourceEvent{Terminal: true, Err: errBind})
	select {
	case <-first.stopped:
	case <-time.After(time.Second):
		t.Fatal("unexpectedly ended NFLOG consumer was not stopped")
	}

	for attempt := 2; attempt <= 3; attempt++ {
		r := nextNFLogRegistration(t, registrations)
		select {
		case <-r.stopped:
		case <-time.After(time.Second):
			t.Fatalf("failed NFLOG attempt %d was not stopped", attempt)
		}
	}
	awaitNFLogState(t, e, "failed")
	deadline := time.Now().Add(time.Second)
	for e.nflogOwner.Load() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if owner := e.nflogOwner.Load(); owner != nil {
		t.Fatal("ended NFLOG supervisor retained its ownership slot")
	}

	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatalf("RetryProtection after unexpected end: %v", err)
	}
	rebound := nextNFLogRegistration(t, registrations)
	if got := protectionComponent(t, e.Protection(), "nflog").State; got != "ready" {
		t.Fatalf("NFLOG state after retry = %q, want ready", got)
	}
	select {
	case <-rebound.ctx.Done():
		t.Fatalf("rebound NFLOG consumer did not use engine lifetime: %v", rebound.ctx.Err())
	default:
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
	startNFLog = func(_ context.Context, _ uint16, sink capture.RuleHitSink, _ func(error), _ func(capture.SourceEvent)) (func(), error) {
		hits, ok := sink.(nflogRuleHits)
		if !ok {
			return func() {}, errors.New("unexpected NFLOG sink type")
		}
		store := hits.e.Events()

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
	startNFLog = func(context.Context, uint16, capture.RuleHitSink, func(error), func(capture.SourceEvent)) (func(), error) {
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
