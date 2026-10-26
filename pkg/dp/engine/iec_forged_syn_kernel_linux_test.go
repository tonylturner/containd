// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

var (
	iecStartdtAct = []byte{0x68, 0x04, 0x07, 0, 0, 0}
	iecStartdtCon = []byte{0x68, 0x04, 0x0B, 0, 0, 0}
)

// startIECStation runs an IEC 104 controlled station that answers STARTDT
// act with STARTDT con.
func startIECStation(t *testing.T) *kernelServer {
	t.Helper()
	return startKernelServer(t, iec104Port, func(_ string, buf []byte) (int, []byte, error) {
		if len(buf) < 2 || len(buf) < 2+int(buf[1]) {
			return 0, nil, nil
		}
		apdu := buf[:2+int(buf[1])]
		if bytes.Equal(apdu, iecStartdtAct) {
			return len(apdu), iecStartdtCon, nil
		}
		return len(apdu), nil, nil
	})
}

// startIECEngine runs the engine with one enforce IEC 104 envelope from the
// client namespace to the station.
func startIECEngine(t *testing.T, ctx context.Context) *Engine {
	t.Helper()
	return startKernelEngine(t, ctx, rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
		ID: "iec104-station", Sources: []string{"198.18.50.0/24"}, Destinations: []string{fcServerIP + "/32"},
		Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(iec104Port)}},
		ICS:       rules.ICSPredicate{Protocol: "iec104"}, Action: rules.ActionAllow,
	}}})
}

// startdt sends STARTDT act and requires STARTDT con.
func (c *fcClient) startdt() {
	c.t.Helper()
	c.write(iecStartdtAct)
	_ = c.conn.SetReadDeadline(time.Now().Add(fcReplyWait))
	reply := make([]byte, len(iecStartdtCon))
	if _, err := io.ReadFull(c.conn, reply); err != nil || !bytes.Equal(reply, iecStartdtCon) {
		c.t.Fatalf("STARTDT from %s: % x, %v; want STARTDT con", c.src, reply, err)
	}
}

// TestIECForgedSYNKernelRestartPickup runs in the first-command kernel lab
// (see first_command_kernel_linux_test.go for how to run it). After an
// engine restart under an open IEC 104 connection that the stopping engine
// did not close, a SYN is sent in that connection whose sequence number
// would start a session at the client's next byte. Connection tracking
// still holds the connection established, so the SYN opens no session:
// the station's challenge ACK is a packet of a session not observed from
// its SYN, and the engine resets the connection at both endpoints. No byte
// reaches the station after the restart, and the client's next
// connection, from the same source port, starts a session at its
// handshake.
func TestIECForgedSYNKernelRestartPickup(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startIECStation(t)
	e := startIECEngine(t, ctx)
	// The engine stops as a crashed one does: the resets and conntrack
	// deletes that would close its sessions go nowhere.
	e.iec.injector = &session.Fake{}
	e.iec.ctDelete = func(context.Context, conntrack.DeleteRequest) error { return nil }

	const src = "198.18.50.46"
	fcRun(ctx, t, "ip", "-n", fcClientNS, "addr", "add", src+"/24", "dev", "fcp0")
	c, _ := dialFrom(ctx, t, src, 0, iec104Port)
	c.startdt()
	restartFirstCommandEngine(ctx, t, e, nil)
	before := srv.received(src)

	start := time.Now()
	c.forgeSYN(iec104Port)
	c.expectReset()
	t.Logf("connection reset %v after the SYN", time.Since(start))
	if ends := srv.ended(t, src, 1); !errors.Is(ends[0], syscall.ECONNRESET) {
		t.Fatalf("station connection ended with %v, want a reset", ends[0])
	}
	if got := srv.received(src); got != before {
		t.Fatalf("station received %d bytes after the restart", got-before)
	}

	port := c.localPort()
	_ = c.conn.Close()
	next, took := dialFrom(ctx, t, src, port, iec104Port)
	t.Logf("reconnect from %s:%d took %v", src, port, took)
	next.startdt()
}
