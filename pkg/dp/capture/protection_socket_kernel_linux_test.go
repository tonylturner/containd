// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func TestProtectionSocketLossKernel(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("requires disposable kernel gate container")
	}
	faults := capture.InstallSocketFaults(t)
	const table = "protection_socket"
	e, err := engine.New(engine.Config{
		NFQueueGroup: 4787, NFLogGroup: 4788, DPIEnabled: true, DPIMode: "enforce",
		ResetInjector: &session.Fake{},
		Enforce: engine.EnforceConfig{
			Enabled: true, TableName: table,
			ClearMark: func(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{table + "_policy", table} {
			if out, err := exec.Command("nft", "delete", "table", "inet", name).CombinedOutput(); err != nil {
				t.Errorf("delete test table %s: %v %s", name, err, out)
			}
		}
	})
	t.Cleanup(e.Close)
	e.BeginProtection("socket-kernel", "apply")
	snap := rules.Snapshot{DPIMode: "enforce", Firewall: []rules.Entry{{
		ID: "iec", Action: rules.ActionAllow, Log: true,
		Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
		ICS:       rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"},
	}}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if err := e.StartWithRetry(context.Background()); err != nil {
		t.Fatal(err)
	}
	await := func(state string) engine.ProtectionStatus {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			st := e.Protection()
			if st.State == state {
				return st
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("want %s: %+v", state, e.Protection())
		return engine.ProtectionStatus{}
	}
	nextClose := func(ch <-chan func() error) func() error {
		t.Helper()
		select {
		case closeSocket := <-ch:
			return closeSocket
		case <-time.After(time.Second):
			t.Fatal("consumer did not open a real socket")
			return nil
		}
	}
	await("protecting")
	queueClose, logClose := nextClose(faults.QueueClose), nextClose(faults.LogClose)
	faults.RejectQueue.Store(true)
	if err := queueClose(); err != nil {
		t.Fatal(err)
	}
	failed := await("failed")
	found := false
	for _, c := range failed.Components {
		if c.Name == "nfqueue:4787" {
			found = true
			if c.State != "failed" || c.Attempt != 3 || c.MaxAttempts != 3 || !strings.HasPrefix(c.Reason, "nfqueue:4787: ") {
				t.Fatalf("supervisor did not publish terminal exhaustion: %+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("missing current queue observation: %+v", failed)
	}
	out, err := exec.Command("nft", "list", "chain", "inet", table+"_policy", "iec104_envelope").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "drop") || strings.Contains(string(out), "queue num") {
		t.Fatalf("real socket loss did not close the envelope: %v %s", err, out)
	}
	t.Log("real NFQUEUE socket close -> receive failure -> supervisor exhaustion -> failed; nft envelope=drop")
	faults.RejectQueue.Store(false)
	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.StartWithRetry(context.Background()); err != nil {
		t.Fatal(err)
	}
	await("protecting")
	faults.RejectLog.Store(true)
	if err := logClose(); err != nil {
		t.Fatal(err)
	}
	degraded := await("degraded")
	if !degraded.Retryable {
		t.Fatalf("lost logging consumer not retryable: %+v", degraded)
	}
	faults.RejectLog.Store(false)
	if err := e.RetryProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	await("protecting")
	t.Log("real NFLOG socket close -> terminal receive callback -> degraded -> explicit retry -> protecting")
}
