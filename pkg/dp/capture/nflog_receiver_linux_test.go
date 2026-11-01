// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

type nfLogTestConn struct {
	mu       sync.Mutex
	requests []netlink.Message
	packets  chan []netlink.Message
	wake     chan struct{}
	closed   atomic.Bool
	failAt   int
}

func newNFLogTestConn() *nfLogTestConn {
	return &nfLogTestConn{packets: make(chan []netlink.Message, 2), wake: make(chan struct{}, 1)}
}
func (c *nfLogTestConn) Execute(m netlink.Message) ([]netlink.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, m)
	if len(c.requests) == c.failAt {
		return nil, errors.New("configuration failed")
	}
	return nil, nil
}
func (c *nfLogTestConn) Receive() ([]netlink.Message, error) {
	select {
	case msgs := <-c.packets:
		return msgs, nil
	case <-c.wake:
		return nil, os.ErrDeadlineExceeded
	}
}
func (c *nfLogTestConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *nfLogTestConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	return nil
}
func (c *nfLogTestConn) Close() error { c.closed.Store(true); return nil }

func nfLogTestPacket(t *testing.T, group uint16, attrs ...netlink.Attribute) netlink.Message {
	t.Helper()
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfLogSubsystem << 8)},
		Data:   append([]byte{2, 0, byte(group >> 8), byte(group)}, data...),
	}
}

func TestNFLogReceiverConfigurationAndImmediateClose(t *testing.T) {
	for range 100 {
		conn := newNFLogTestConn()
		r := &nfLogReceiver{conn: conn, group: 4788}
		if err := r.Start(context.Background(), func(nfLogAttribute) {}, func(error) bool { return false }); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if !conn.closed.Load() {
			t.Fatal("Close did not release socket")
		}
		if len(conn.requests) != 3 {
			t.Fatalf("bind/config/unbind: %+v", conn.requests)
		}
		wantAttrs := [][]netlink.Attribute{
			{{Type: nfLogCmd, Data: []byte{nfLogBind}}},
			{{Type: nfLogMode, Data: []byte{0, 0, 0, 0, 2, 0}}, {Type: nfLogFlags, Data: []byte{0, 4}}},
			{{Type: nfLogCmd, Data: []byte{nfLogUnbind}}},
		}
		for i, req := range conn.requests {
			want, err := netlink.MarshalAttributes(wantAttrs[i])
			if err != nil {
				t.Fatal(err)
			}
			if req.Header.Type != 0x401 || req.Header.Flags != netlink.Request|netlink.Acknowledge ||
				!bytes.Equal(req.Data[:4], []byte{0, 0, 0x12, 0xb4}) || !bytes.Equal(req.Data[4:], want) {
				t.Fatalf("request %d: %+v", i, req)
			}
		}
		if err := r.Start(context.Background(), nil, nil); err == nil {
			t.Fatal("closed receiver restarted")
		}
	}
}

func TestNFLogReceiverCloseJoinsHook(t *testing.T) {
	conn := newNFLogTestConn()
	r := &nfLogReceiver{conn: conn, group: 77}
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	if err := r.Start(context.Background(), func(nfLogAttribute) {
		calls.Add(1)
		close(entered)
		<-release
	}, func(error) bool { return false }); err != nil {
		t.Fatal(err)
	}
	packet := nfLogTestPacket(t, 77, netlink.Attribute{Type: nfLogPrefix, Data: []byte("containd:test:ALLOW \x00")})
	conn.packets <- []netlink.Message{packet, packet}
	<-entered
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	// Cancellation proves Close has begun, without relying on scheduling.
	<-conn.wake
	select {
	case <-done:
		t.Fatal("Close returned before the hook finished")
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !conn.closed.Load() {
		t.Fatal("hooks continued after cancellation or socket was not closed")
	}
}

func TestNFLogReceiverParentCancellationAndSetupFailure(t *testing.T) {
	conn := newNFLogTestConn()
	r := &nfLogReceiver{conn: conn, group: 77}
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx, func(nfLogAttribute) {}, func(error) bool {
		t.Error("cancellation reported as source failure")
		return false
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-r.done
	if err := r.Close(); err != nil || !conn.closed.Load() {
		t.Fatalf("parent cancellation: %v closed=%v", err, conn.closed.Load())
	}
	for _, failAt := range []int{1, 2} {
		conn := newNFLogTestConn()
		conn.failAt = failAt
		r := &nfLogReceiver{conn: conn, group: 77}
		if err := r.Start(context.Background(), nil, nil); err == nil {
			t.Fatal("setup failure accepted")
		}
		if err := r.Close(); err != nil || !conn.closed.Load() {
			t.Fatalf("setup cleanup: %v closed=%v", err, conn.closed.Load())
		}
	}
}

func TestNFLogReceiverPacketAndReceiveErrors(t *testing.T) {
	conn := newNFLogTestConn()
	r := &nfLogReceiver{conn: conn, group: 77}
	hits, errs := make(chan struct{}, 2), make(chan struct{}, 2)
	errorCalls := 0
	if err := r.Start(context.Background(), func(nfLogAttribute) { hits <- struct{}{} }, func(error) bool {
		errorCalls++
		errs <- struct{}{}
		return errorCalls < 2
	}); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	conn.wake <- struct{}{}
	<-errs
	packet := nfLogTestPacket(t, 77, netlink.Attribute{Type: nfLogPrefix, Data: []byte("containd:test:ALLOW \x00")})
	conn.packets <- []netlink.Message{
		{Header: netlink.Header{Type: netlink.Done}},
		{Header: packet.Header, Data: []byte{1}}, // malformed packet is local
		nfLogTestPacket(t, 78),                   // foreign group
		packet,
	}
	<-hits
	// Wait until the first receive error has actually been handled.
	// A second error ends the receiver, not just the current packet batch.
	conn.wake <- struct{}{}
	<-r.done
	if errorCalls != 2 || len(hits) != 0 || !conn.closed.Load() {
		t.Fatalf("errors=%d extra hits=%d closed=%v", errorCalls, len(hits), conn.closed.Load())
	}
}

func TestNFLogReceiverAttributeParsing(t *testing.T) {
	ct := make([]byte, 4)
	binary.BigEndian.PutUint32(ct, 3)
	msg := nfLogTestPacket(t, 77,
		netlink.Attribute{Type: nfLogPrefix, Data: []byte("containd:test:ALLOW \x00")},
		netlink.Attribute{Type: nfLogPayload, Data: []byte{0x45, 1, 2}},
		netlink.Attribute{Type: nfLogCTInfo, Data: ct},
		netlink.Attribute{Type: 123, Data: []byte{1}}, // unrelated UAPI fields ignored
	)
	a, err := parseNFLog(msg.Data, 77)
	if err != nil || a.Prefix == nil || *a.Prefix != "containd:test:ALLOW " ||
		a.Payload == nil || !bytes.Equal(*a.Payload, []byte{0x45, 1, 2}) || a.CtInfo == nil || *a.CtInfo != 3 {
		t.Fatalf("decoded %+v: %v", a, err)
	}
	for _, data := range [][]byte{nil, {2, 0, 0}, {2, 1, 0, 77}, {2, 0, 0, 78},
		append([]byte{2, 0, 0, 77}, 3, 0, 19, 0)} {
		if _, err := parseNFLog(data, 77); err == nil {
			t.Fatalf("accepted malformed header/attributes: %x", data)
		}
	}
	shortCT := nfLogTestPacket(t, 77, netlink.Attribute{Type: nfLogCTInfo, Data: []byte{1}})
	if _, err := parseNFLog(shortCT.Data, 77); err == nil {
		t.Fatal("accepted truncated conntrack direction")
	}
}
