// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

func timestampControl(t *testing.T, level, kind int32, ts unix.Timespec) []byte {
	t.Helper()
	b := make([]byte, unix.CmsgSpace(afPacketTimespecSize))
	h := unix.Cmsghdr{Level: level, Type: kind}
	h.SetLen(unix.CmsgLen(afPacketTimespecSize))
	if _, err := binary.Encode(b, binary.NativeEndian, h); err != nil {
		t.Fatal(err)
	}
	if _, err := binary.Encode(b[unix.CmsgLen(0):], binary.NativeEndian, ts); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAFPacketKernelTimestamp(t *testing.T) {
	want := time.Unix(1_700_000_000, 123456789).UTC()
	ts := unix.NsecToTimespec(want.UnixNano())
	valid := timestampControl(t, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, ts)
	short := timestampControl(t, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, ts)
	header := unix.Cmsghdr{Level: unix.SOL_SOCKET, Type: unix.SO_TIMESTAMPNS}
	header.SetLen(unix.CmsgLen(afPacketTimespecSize - 1))
	if _, err := binary.Encode(short, binary.NativeEndian, header); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		oob   []byte
		flags int
		ok    bool
	}{
		{name: "valid", oob: valid, ok: true},
		{name: "packet truncated but timestamp intact", oob: valid, flags: unix.MSG_TRUNC, ok: true},
		{name: "unrelated then timestamp", oob: append(timestampControl(t, unix.SOL_SOCKET, unix.SO_TIMESTAMP, ts), valid...), ok: true},
		{name: "absent"},
		{name: "truncated header", oob: valid[:unix.CmsgLen(0)-1]},
		{name: "truncated payload", oob: valid[:unix.CmsgLen(afPacketTimespecSize)-1]},
		{name: "short timespec", oob: short},
		{name: "control truncation flag", oob: valid, flags: unix.MSG_CTRUNC},
		{name: "wrong level", oob: timestampControl(t, unix.SOL_PACKET, unix.SO_TIMESTAMPNS, ts)},
		{name: "wrong type", oob: timestampControl(t, unix.SOL_SOCKET, unix.SO_TIMESTAMP, ts)},
		{name: "negative nanoseconds", oob: timestampControl(t, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, unix.Timespec{Sec: ts.Sec, Nsec: -1})},
		{name: "overflowing nanoseconds", oob: timestampControl(t, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, unix.Timespec{Sec: ts.Sec, Nsec: 1_000_000_000})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := afPacketKernelTimestamp(tc.oob, tc.flags)
			if ok != tc.ok || (ok && (!got.Equal(want) || got.Location() != time.UTC)) {
				t.Fatalf("timestamp = %v, %v; want %v, %v", got, ok, want, tc.ok)
			}
			beforeCount := testutil.ToFloat64(afPacketTimestampFallbacks)
			before := time.Now()
			got = afPacketReceiveTime(tc.oob, tc.flags)
			after := time.Now()
			wantCount := beforeCount
			if tc.ok {
				if !got.Equal(want) {
					t.Fatalf("kernel timestamp changed to %v", got)
				}
			} else {
				wantCount++
				if got.Before(before) || got.After(after) {
					t.Fatalf("fallback %v outside [%v, %v]", got, before, after)
				}
			}
			if got.Location() != time.UTC {
				t.Fatalf("timestamp location = %v, want UTC", got.Location())
			}
			if count := testutil.ToFloat64(afPacketTimestampFallbacks); count != wantCount {
				t.Fatalf("fallback count = %v, want %v", count, wantCount)
			}
		})
	}
}

// TestAFPacketKernelReceiveTime queues two loopback packets while the worker is
// blocked in its handler. Both timestamps must precede the worker's next read,
// stay within their send intervals, and preserve send order. CAP_NET_RAW is
// required; no nftables binary or network configuration changes are needed.
func TestAFPacketKernelReceiveTime(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") == "1" {
			t.Fatal("kernel AF_PACKET test requires root with CAP_NET_RAW")
		}
		t.Skip("kernel AF_PACKET test requires root with CAP_NET_RAW")
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := make(chan struct{}, 1)
	release := make(chan struct{})
	packets := make(chan Packet, 4)
	done := make(chan error, 1)
	w := &worker{
		iface: "lo",
		cfg:   Config{Snaplen: 2048},
		handler: func(p Packet) Decision {
			if p.SrcPort != uint16(client.LocalAddr().(*net.UDPAddr).Port) ||
				p.DstPort != uint16(server.LocalAddr().(*net.UDPAddr).Port) {
				return Decision{}
			}
			if string(p.Payload) == "ready" {
				select {
				case ready <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-ctx.Done():
				}
			} else {
				select {
				case packets <- p:
				case <-ctx.Done():
				}
			}
			return Decision{}
		},
	}
	go func() { done <- w.run(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("capture worker: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("capture worker did not stop")
		}
	}()
	send := func(payload string) {
		t.Helper()
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		n, _, err := server.ReadFromUDP(b)
		if err != nil || !bytes.Equal(b[:n], []byte(payload)) {
			t.Fatalf("loopback read = %q, %v; want %q", b[:n], err, payload)
		}
	}
	// Worker startup is asynchronous. Probe until a packet reaches its handler,
	// rather than assuming a sleep means the raw socket has been bound.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
probe:
	for {
		send("ready")
		select {
		case <-ready:
			break probe
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("capture worker did not receive the readiness probe")
		}
	}

	beforeCount := testutil.ToFloat64(afPacketTimestampFallbacks)
	var before, after [2]time.Time
	for i, payload := range []string{"first", "second"} {
		before[i] = time.Now()
		send(payload)
		after[i] = time.Now()
		time.Sleep(10 * time.Millisecond)
	}
	readNotBefore := time.Now()
	close(release)
	var previous time.Time
	for i, payload := range []string{"first", "second"} {
		select {
		case p := <-packets:
			if string(p.Payload) != payload {
				t.Fatalf("packet %d payload = %q, want %q", i, p.Payload, payload)
			}
			if p.Timestamp.Before(before[i]) || p.Timestamp.After(after[i]) ||
				!p.Timestamp.Before(readNotBefore) || !p.Timestamp.After(previous) ||
				p.Timestamp.Location() != time.UTC {
				t.Fatalf("packet %d timestamp %v; send [%v, %v], read after %v, previous %v",
					i, p.Timestamp, before[i], after[i], readNotBefore, previous)
			}
			previous = p.Timestamp
		case <-ctx.Done():
			t.Fatal("capture worker did not deliver the queued packets")
		}
	}
	if count := testutil.ToFloat64(afPacketTimestampFallbacks); count != beforeCount {
		t.Fatalf("kernel timestamp missing: fallback count increased from %v to %v", beforeCount, count)
	}
}
