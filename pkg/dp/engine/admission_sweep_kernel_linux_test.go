// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestEngineKernelVerdictDuringAdmissionSweep(t *testing.T) {
	admissionKernel(t)
	for _, tc := range []struct {
		name string
		mask uint32
	}{
		{"parity", markabi.AdmittedBit},
		{"retired gate index", enforce.GateZoneCtMask},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newFirstCommandLab(t)
			e, err := New(Config{Enforce: EnforceConfig{Enabled: true}, NFQueueGroup: fcQueue})
			if err != nil {
				t.Fatal(err)
			}
			type completion struct {
				verdict capture.Verdict
				err     error
			}
			completed := make(chan completion, 1)
			manager, err := capture.NewManager(capture.Config{
				Mode: "nfqueue", QueueID: int(fcQueue), PublicationFence: &e.policyMu,
				OnSource: e.hooks.onSource,
				OnVerdict: func(tok capture.Token, v capture.Verdict, err error) {
					e.hooks.onVerdict(tok, v, err)
					completed <- completion{v, err}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			e.capture = heldKernelCapture{manager, func(pkt capture.Packet) capture.Decision {
				d := e.HandlePacket(pkt)
				d.Notify = true
				return d
			}}
			if err := e.Start(ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				fresh, err := New(Config{})
				if err == nil {
					err = e.Reconfigure(fresh)
				}
				if err != nil {
					t.Error(err)
				}
			})
			snap := rules.Snapshot{Default: rules.ActionDeny,
				Gate: rules.GateSelection{Zones: []rules.GateZone{{Name: "old", Index: 1}}},
				Firewall: []rules.Entry{{
					ID: "queued", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "44818"}},
					ICS: rules.ICSPredicate{Protocol: "cip", Mode: "enforce"},
				}}}
			if err := e.ApplyRules(ctx, snap); err != nil {
				t.Fatal(err)
			}
			var server, client *net.UDPConn
			if err := inNetns(fcServerNS, func() (err error) {
				server, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(fcServerIP), Port: 44818})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err := inNetns(fcClientNS, func() (err error) {
				client, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(fcServerIP), Port: 44818})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			sweeping, release, applied := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			clearMarks := e.clearMarks
			e.clearMarks = func(ctx context.Context, mask, value, clear uint32) (int, error) {
				if clear == tc.mask {
					close(sweeping)
					<-release
				}
				return clearMarks(ctx, mask, value, clear)
			}
			snap.Gate.Zones = nil
			var applyErr error
			t.Cleanup(func() {
				unblock()
				<-applied
			})
			go func() {
				defer close(applied)
				applyErr = e.ApplyRules(ctx, snap)
			}()
			select {
			case <-sweeping:
			case <-time.After(3 * time.Second):
				t.Fatal("apply did not reach sweep")
			}
			if _, err := client.Write([]byte("during-sweep")); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-completed:
				if got.err != nil || got.verdict != capture.VerdictRepeat {
					t.Fatalf("kernel verdict=%+v", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SetVerdict did not complete during the sweep")
			}
			if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, err := server.Read(buf)
			if err != nil || string(buf[:n]) != "during-sweep" {
				t.Fatalf("delivery during sweep=%q err=%v", buf[:n], err)
			}
			select {
			case <-applied:
				t.Fatal("apply completed before sweep was released")
			default:
			}
			unblock()
			<-applied
			if applyErr != nil {
				t.Fatal(applyErr)
			}
		})
	}
}
