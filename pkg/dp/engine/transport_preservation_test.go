// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestInspectionSnapshotDuringReconfigure(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				inputs := e.InspectionSnapshot()
				if len(inputs.Parsing) != 4 {
					t.Error("partial parsing profile")
					return
				}
			}
		}
	})
	defer func() { close(stop); readers.Wait() }()
	for range 10 {
		fresh, err := New(Config{Events: e.Events()})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Reconfigure(fresh); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInspectionSnapshotCreatesIndependentOfflineDecoders(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	inputs := e.InspectionSnapshot()
	fresh, err := inputs.NewDecoders()
	if err != nil || len(fresh) != len(inputs.Decoders) {
		t.Fatal("offline registry changed enabled protocols", err)
	}
	for i := range fresh {
		// Zero-sized stateless decoder pointers may legally compare equal.
		if reflect.TypeOf(fresh[i]).Elem().Size() > 0 && fresh[i] == inputs.Decoders[i] {
			t.Fatal("offline import shares live decoder state")
		}
	}
}

func TestTransportReconfigurePreservesExplicitWatchHook(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	e.SetLearnWatchHook(func(*flow.State, []dpi.Event) {})
	hook := e.learnWatch.Load()
	fresh, err := New(Config{Events: e.Events()})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if e.learnWatch.Load() != hook {
		t.Fatal("reconfigure discarded the explicit collector")
	}
}

func TestTransportRawSYNDoesNotChangeDenyISNs(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	e.HandlePacket(pkt)
	e.flowMu.Lock()
	st := e.tupleStateLocked(natEvidence().Original)
	_, denyRecorded := e.tcpISNs[st.Key.MapKey()]
	rawRecorded := e.transportISNs[st.Key.MapKey()] == 100
	e.flowMu.Unlock()
	e.HandlePacket(pkt) // retransmission must retain the incarnation
	e.flowMu.Lock()
	same := e.tupleStateLocked(natEvidence().Original) == st
	e.flowMu.Unlock()
	if denyRecorded || !rawRecorded || !same {
		t.Fatal("raw capture SYN changed deny semantics or retired its retransmission")
	}
}

func TestTransportRawSYNExpiryCleansISNs(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	e.HandlePacket(pkt)
	if len(e.transportISNs) != 1 {
		t.Fatal("missing transport hint")
	}
	e.sweepFlows(pkt.Timestamp.Add(10 * time.Minute))
	if len(e.transportISNs) != 0 {
		t.Fatal("expired connection leaked transport ISN")
	}
}
