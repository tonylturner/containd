// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package session

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

func TestNewInjectorUnsupported(t *testing.T) {
	inj, err := NewInjector()
	if !errors.Is(err, ErrUnsupportedPlatform) || inj != nil {
		t.Fatalf("NewInjector = %v, %v; want nil, ErrUnsupportedPlatform", inj, err)
	}
}

func TestFakeRecordsResetsAndErrors(t *testing.T) {
	client := netip.MustParseAddrPort("10.60.60.10:40000")
	server := netip.MustParseAddrPort("10.70.0.5:2404")
	toServer := Reset{Src: client, Dst: server, Seq: 1001}
	toClient := Reset{Src: server, Dst: client, Seq: 5001}

	f := &Fake{}
	var inj Injector = f
	if err := inj.SendRST(toServer); err != nil {
		t.Fatalf("SendRST: %v", err)
	}
	sendErr := errors.New("sendto: no route")
	f.SetError(sendErr)
	if err := inj.SendRST(toClient); !errors.Is(err, sendErr) {
		t.Fatalf("SendRST err = %v, want configured error", err)
	}
	if got := f.Resets(); !reflect.DeepEqual(got, []Reset{toServer, toClient}) {
		t.Fatalf("Resets = %+v", got)
	}
	f.Resets()[0].Seq = 0
	if f.Resets()[0].Seq != 1001 {
		t.Fatal("Resets must return a copy")
	}
	if err := inj.Close(); err != nil || !f.Closed() {
		t.Fatalf("Close = %v closed=%v", err, f.Closed())
	}
	if err := inj.SendRST(toServer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SendRST after Close = %v, want net.ErrClosed", err)
	}
}

func TestFakeConcurrentUse(t *testing.T) {
	f := &Fake{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(seq uint32) {
			defer wg.Done()
			_ = f.SendRST(Reset{Seq: seq})
			f.SetError(nil)
		}(uint32(i))
	}
	wg.Wait()
	if got := len(f.Resets()); got != 8 {
		t.Fatalf("recorded %d resets, want 8", got)
	}
}
