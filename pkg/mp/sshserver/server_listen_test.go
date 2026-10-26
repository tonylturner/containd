// SPDX-License-Identifier: Apache-2.0

package sshserver

import (
	"context"
	"errors"
	"net"
	"testing"
)

// Listen reports a failed bind before it returns and leaves nothing to
// serve; Serve refuses to run without a bound socket.
func TestListenReportsBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	srv, _, _ := newTestSSHServer(t)
	srv.opts.ListenAddr = occupied.Addr().String()
	err = srv.Listen(context.Background())
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" {
		t.Fatalf("Listen on an occupied address = %v", err)
	}
	if addr := srv.Addr(); addr != nil {
		t.Fatalf("Addr after a failed bind = %v", addr)
	}
	if err := srv.Serve(context.Background()); err == nil || err.Error() != "ssh server is not listening" {
		t.Fatalf("Serve without a bound socket = %v", err)
	}
}

// Listen binds before it returns: the socket accepts connections at Addr,
// and a second Listen does not replace it.
func TestListenBindsBeforeServe(t *testing.T) {
	srv, _, _ := newTestSSHServer(t)
	srv.opts.ListenAddr = "127.0.0.1:0"
	if err := srv.Listen(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	addr := srv.Addr()
	if addr == nil {
		t.Fatal("no address after Listen")
	}
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial the bound socket: %v", err)
	}
	_ = conn.Close()
	if err := srv.Listen(context.Background()); err == nil || err.Error() != "ssh server already listening" {
		t.Fatalf("second Listen = %v", err)
	}
	if got := srv.Addr(); got.String() != addr.String() {
		t.Fatalf("Addr = %v after a second Listen, want %v", got, addr)
	}
}
