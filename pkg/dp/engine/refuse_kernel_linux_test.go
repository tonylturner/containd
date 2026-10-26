// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// fcRefuseBound bounds a refused connect: the server's RST must reach the
// client before its first SYN retransmission, one second after its SYN.
const fcRefuseBound = 500 * time.Millisecond

// fcRefusedPort is the client port of the refused connections and of the
// connections that follow them.
const fcRefusedPort = 41090

// dialRefused connects from src:port to dport, where nothing listens, and
// requires the connect to be refused within fcRefuseBound.
func dialRefused(ctx context.Context, t *testing.T, src string, port, dport int) {
	t.Helper()
	start := time.Now()
	err := inNetns(fcClientNS, func() error {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src), Port: port}, Timeout: 2 * fcReconnectBound}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(fcServerIP, strconv.Itoa(dport)))
		if err == nil {
			_ = c.Close()
		}
		return err
	})
	took := time.Since(start)
	t.Logf("connect from %s:%d ended after %v: %v", src, port, took, err)
	if !errors.Is(err, syscall.ECONNREFUSED) || took > fcRefuseBound {
		t.Fatalf("connect from %s:%d: %v after %v; want refused within %v", src, port, err, took, fcRefuseBound)
	}
}

// TestIECRefusedKernel runs in the first-command kernel lab (see
// first_command_kernel_linux_test.go for how to run it). A client connects
// through an enforce IEC 104 envelope to a station that does not listen
// yet: the station's RST reaches the client, which fails at once. Once the
// station listens, the client's next connection from the same port opens
// the next session.
func TestIECRefusedKernel(t *testing.T) {
	ctx := newFirstCommandLab(t)
	startIECEngine(t, ctx)

	const src = "198.18.50.51"
	fcRun(ctx, t, "ip", "-n", fcClientNS, "addr", "add", src+"/24", "dev", "fcp0")
	dialRefused(ctx, t, src, fcRefusedPort, iec104Port)
	startIECStation(t)
	next, took := dialFrom(ctx, t, src, fcRefusedPort, iec104Port)
	t.Logf("connect from %s:%d took %v", src, fcRefusedPort, took)
	next.startdt()
}

// TestRefusedKernel is TestIECRefusedKernel's refused connect for a Modbus
// connection in an enforce ICS rule's scope: generic ICS rules queue only
// the client's direction, so the server's RST reaches the client without
// the engine.
func TestRefusedKernel(t *testing.T) {
	ctx := newFirstCommandLab(t)
	startFirstCommandEngine(t, ctx)

	const src = "198.18.50.52"
	fcRun(ctx, t, "ip", "-n", fcClientNS, "addr", "add", src+"/24", "dev", "fcp0")
	dialRefused(ctx, t, src, fcRefusedPort, 502)
}
