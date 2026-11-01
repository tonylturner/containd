// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// occupyProtectionQueue returns only after successful registration, not merely
// socket creation. It never infers the cause of a later bind error from errno.
func occupyProtectionQueue(t *testing.T, group uint16) (func(), *atomic.Int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	q, err := nfqueue.Open(&nfqueue.Config{NfQueue: group, MaxPacketLen: 65535, MaxQueueLen: 1024, Copymode: nfqueue.NfQnlCopyPacket})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	count := &atomic.Int64{}
	if err := q.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		count.Add(1)
		if a.PacketID != nil {
			_ = q.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		return 0
	}, func(error) int { return 1 }); err != nil {
		cancel()
		_ = q.Close()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); _ = q.Close() }) }
	t.Cleanup(stop)
	return stop, count
}

func waitProtection(t *testing.T, e *Engine, state string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e.Protection().State == state {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("want %s: %+v", state, e.Protection())
}

func protectionKernelConfig(e *Engine) Config {
	return Config{Events: e.Events(), Enforce: EnforceConfig{Enabled: true, TableName: "containd"}, DPIEnabled: true, DPIMode: "enforce", NFQueueGroup: fcQueue}
}

func TestProtectionBindKernel(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("requires disposable kernel gate container")
	}
	t.Run("exclusive bind", func(t *testing.T) {
		_, _ = occupyProtectionQueue(t, 4789)
		q, err := nfqueue.Open(&nfqueue.Config{NfQueue: 4789, MaxPacketLen: 65535, MaxQueueLen: 1024, Copymode: nfqueue.NfQnlCopyPacket})
		if err != nil {
			t.Fatal(err)
		}
		defer q.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err = q.RegisterWithErrorFunc(ctx, func(nfqueue.Attribute) int { return 0 }, func(error) int { return 1 })
		if err == nil {
			t.Fatal("second bind succeeded on occupied queue")
		}
		t.Logf("occupied queue bind rejected (no errno inference): %v", err)
	})
	t.Run("envelope exhaustion and retry", func(t *testing.T) {
		fastRetry(t, 3)
		ctx := newFirstCommandLab(t)
		srv := startIECStation(t)
		e := startIECEngine(t, ctx)
		snap := *e.CurrentRules()
		e.BeginProtection("kernel", "positive")
		if err := e.ApplyRules(ctx, snap); err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		client, _ := dialFrom(ctx, t, "198.18.50.2", 0, iec104Port)
		client.startdt()
		_ = client.conn.Close()
		t.Log("positive control: STARTDT con returned on the live path")
		before := srv.received("198.18.50.2")
		e.BeginProtection("kernel", "occupied")
		fresh, err := New(protectionKernelConfig(e))
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Reconfigure(fresh); err != nil {
			t.Fatal(err)
		}
		release, packets := occupyProtectionQueue(t, fcQueue)
		if err = e.ApplyRules(ctx, snap); err != nil {
			t.Fatal(err)
		}
		if e.Protection().State != "pending" {
			t.Fatalf("before bind: %+v", e.Protection())
		}
		err = e.StartWithRetry(ctx)
		if err == nil {
			t.Fatal("occupied queue bound")
		}
		waitProtection(t, e, "failed")
		component := protectionComponent(t, e.Protection(), fmt.Sprintf("nfqueue:%d", fcQueue))
		if !strings.HasPrefix(component.Reason, fmt.Sprintf("nfqueue:%d: ", fcQueue)) {
			t.Fatalf("reason: %s", component.Reason)
		}
		chain := fcRun(ctx, t, "nft", "list", "chain", "inet", "containd_policy", "iec104_envelope")
		if !strings.Contains(chain, "drop") || strings.Contains(chain, "queue num") {
			t.Fatalf("envelope not closed: %s", chain)
		}
		err = inNetns(fcClientNS, func() error {
			conn, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", fcServerIP, iec104Port), 250*time.Millisecond)
			if err == nil {
				defer conn.Close()
				_, _ = conn.Write(iecStartdtAct)
			}
			return err
		})
		if err == nil {
			t.Fatal("connection crossed the closed envelope")
		}
		if got := srv.received("198.18.50.2"); got != before {
			t.Fatalf("station received %d bytes behind closed envelope", got-before)
		}
		if got := packets.Load(); got != 0 {
			t.Fatalf("competing consumer received %d envelope packets", got)
		}

		t.Logf("failed with %s; envelope=drop, station unchanged, competitor packets=%d", component.Reason, packets.Load())
		release()
		old := e.hooks
		if err := e.RetryProtection(ctx); err != nil {
			t.Fatal(err)
		}
		old.onSource(capture.SourceEvent{Ready: true, Generation: 999})
		if e.Protection().State != "pending" {
			t.Fatal("retired ready advanced retry before new bind")
		}
		if err := e.StartWithRetry(ctx); err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		next, _ := dialFrom(ctx, t, "198.18.50.2", 0, iec104Port)
		next.startdt()
		_ = next.conn.Close()
		// Simulate the supervisor's terminal notification after a real socket
		// loss. Its budget/reset/once semantics are tested in capture.
		e.runCapture.Stop()
		e.hooks.onSource(capture.SourceEvent{Terminal: true, Err: fmt.Errorf("consumer exhausted")})
		waitProtection(t, e, "failed")
		if err := e.RetryProtection(ctx); err != nil {
			t.Fatal(err)
		}
		if err := e.StartWithRetry(ctx); err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		t.Log("exhaustion and post-ready loss: retire+join+rebind restored protecting")
	})
	for _, protocol := range []string{"iec104", "modbus"} {
		t.Run("direct "+protocol, func(t *testing.T) {
			fastRetry(t, 3)
			ctx := newFirstCommandLab(t)
			e := startIECEngine(t, ctx)
			snap := rules.Snapshot{DPIMode: "monitor", Firewall: []rules.Entry{{ID: "direct", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: protocol, Mode: "monitor"}}}}
			e.BeginProtection("kernel", "direct")
			fresh, err := New(protectionKernelConfig(e))
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Reconfigure(fresh); err != nil {
				t.Fatal(err)
			}
			release, _ := occupyProtectionQueue(t, fcQueue)
			if err = e.ApplyRules(ctx, snap); err != nil {
				t.Fatal(err)
			}
			if err = e.StartWithRetry(ctx); err == nil {
				t.Fatal("occupied bind succeeded")
			}
			st := e.Protection()
			if st.State != "failed" || len(st.Effects) != 1 || st.Effects[0].Effect != "not_inspected" {
				t.Fatalf("direct-queue state: %+v", st)
			}
			release()
			if err = e.RetryProtection(ctx); err != nil {
				t.Fatal(err)
			}
			if err = e.StartWithRetry(ctx); err != nil {
				t.Fatal(err)
			}
			waitProtection(t, e, "protecting")
			t.Logf("%s direct queue: failed/not_inspected, then protecting after retry", protocol)
		})
	}
	t.Run("release within budget", func(t *testing.T) {
		fastRetry(t, 8)
		startRetryInitial, startRetryMax = 20*time.Millisecond, 20*time.Millisecond
		ctx := newFirstCommandLab(t)
		startIECStation(t)
		e := startIECEngine(t, ctx)
		snap := *e.CurrentRules()
		e.BeginProtection("kernel", "transient")
		fresh, err := New(protectionKernelConfig(e))
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Reconfigure(fresh); err != nil {
			t.Fatal(err)
		}
		release, _ := occupyProtectionQueue(t, fcQueue)
		if err = e.ApplyRules(ctx, snap); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- e.StartWithRetry(ctx) }()
		deadline := time.Now().Add(time.Second)
		for protectionComponent(t, e.Protection(), fmt.Sprintf("nfqueue:%d", fcQueue)).Attempt == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if e.Protection().State != "pending" {
			t.Fatalf("retry domain not pending: %+v", e.Protection())
		}
		release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		client, _ := dialFrom(ctx, t, "198.18.50.2", 0, iec104Port)
		client.startdt()
		_ = client.conn.Close()
		t.Log("release within retry budget restored protecting and STARTDT con")
	})
	t.Run("NFLOG loss and retry", func(t *testing.T) {
		fastRetry(t, 3)
		startRetryInitial, startRetryMax = 10*time.Millisecond, 10*time.Millisecond
		oldStart := startNFLog
		t.Cleanup(func() { startNFLog = oldStart })
		var fail atomic.Bool
		var stopConsumer func()
		var notify func(capture.SourceEvent)
		startNFLog = func(ctx context.Context, group uint16, sink capture.RuleHitSink, onErr func(error), onSource func(capture.SourceEvent)) (func(), error) {
			if fail.Load() {
				return func() {}, fmt.Errorf("injected registration failure after consumer loss")
			}
			stop, err := capture.StartNFLog(ctx, group, sink, onErr, onSource)
			stopConsumer, notify = stop, onSource
			return stop, err
		}
		ctx := newFirstCommandLab(t)
		e := startIECEngine(t, ctx)
		snap := *e.CurrentRules()
		snap.Firewall[0].Log = true
		e.BeginProtection("kernel", "logging")
		cfg := protectionKernelConfig(e)
		cfg.NFLogGroup = 205
		fresh, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Reconfigure(fresh); err != nil {
			t.Fatal(err)
		}
		if err = e.ApplyRules(ctx, snap); err != nil {
			t.Fatal(err)
		}
		if err = e.StartWithRetry(ctx); err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		fail.Store(true)
		stopConsumer()
		notify(capture.SourceEvent{Terminal: true, Err: fmt.Errorf("consumer lost")})
		waitProtection(t, e, "degraded")
		deadline := time.Now().Add(time.Second)
		for protectionComponent(t, e.Protection(), "nflog").State != "failed" && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !e.Protection().Retryable {
			t.Fatalf("exhausted NFLOG not retryable: %+v", e.Protection())
		}
		captureBefore := e.capture
		fail.Store(false)
		if err = e.RetryProtection(ctx); err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		if e.capture != captureBefore {
			t.Fatal("NFLOG retry retired healthy capture")
		}
		e.runCapture.Stop()
		e.hooks.onSource(capture.SourceEvent{Terminal: true, Err: fmt.Errorf("capture lost with NFLOG healthy")})
		if err = e.RetryProtection(ctx); err != nil {
			t.Fatal(err)
		}
		if err = e.StartWithRetry(ctx); err != nil {
			t.Fatal(err)
		}
		waitProtection(t, e, "protecting")
		if protectionComponent(t, e.Protection(), "nflog").State != "ready" {
			t.Fatal("capture retry forgot healthy NFLOG")
		}
		t.Log("real NFLOG socket loss: degraded, bounded retry exhausted, explicit retry rebound without capture retirement")
	})

}
