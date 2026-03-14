// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func TestDiagReachParsersAndDispatch(t *testing.T) {
	if _, _, _, _, err := parseDiagReachArgs(nil); err == nil || !strings.Contains(err.Error(), "usage: diag reach") {
		t.Fatalf("expected usage error for empty diag reach args, got %v", err)
	}
	src, dst, proto, port, err := parseDiagReachArgs([]string{"lan0", "example.test"})
	if err != nil || src != "lan0" || dst != "example.test" || proto != "tcp" || port != 0 {
		t.Fatalf("unexpected default diag reach parse: src=%q dst=%q proto=%q port=%d err=%v", src, dst, proto, port, err)
	}
	_, _, proto, port, err = parseDiagReachArgs([]string{"lan0", "example.test", "443"})
	if err != nil || proto != "tcp" || port != 443 {
		t.Fatalf("unexpected port shortcut parse: proto=%q port=%d err=%v", proto, port, err)
	}
	_, _, proto, port, err = parseDiagReachArgs([]string{"lan0", "example.test", "udp", "53"})
	if err != nil || proto != "udp" || port != 53 {
		t.Fatalf("unexpected udp parse: proto=%q port=%d err=%v", proto, port, err)
	}
	if _, _, err := parseDiagReachProtocol([]string{"bogus"}); err == nil {
		t.Fatal("expected invalid protocol error")
	}
	if _, err := parseDiagReachOptionalPort("icmp", []string{"7"}); err == nil {
		t.Fatal("expected ICMP port rejection")
	}
	if _, err := parseDiagReachPort("70000"); err == nil {
		t.Fatal("expected invalid port error")
	}

	tbl := newTable("CHECK", "STATUS", "DETAILS")
	runDiagReachProbe(context.Background(), tbl, diagReachRequest{proto: "tcp"})
	runDiagReachProbe(context.Background(), tbl, diagReachRequest{proto: "udp"})
	runDiagReachProbe(context.Background(), tbl, diagReachRequest{proto: "invalid"})
	var out bytes.Buffer
	tbl.render(&out)
	rendered := out.String()
	if !strings.Contains(rendered, "no port provided") || !strings.Contains(rendered, "invalid protocol") {
		t.Fatalf("unexpected diag reach table output:\n%s", rendered)
	}
}

func TestDiagnosticsHelperFormatting(t *testing.T) {
	if !isRawSocketDenied(syscall.EPERM) {
		t.Fatal("expected EPERM to be treated as raw-socket denial")
	}
	if !isRawSocketDenied(&net.OpError{Err: syscall.EACCES}) {
		t.Fatal("expected wrapped EACCES to be treated as raw-socket denial")
	}
	if got := rawSocketHint(syscall.EPERM); got == nil || !strings.Contains(got.Error(), "CAP_NET_RAW") {
		t.Fatalf("unexpected rawSocketHint: %v", got)
	}

	if _, _, err := parseDiagPingArgs(nil); err == nil || !strings.Contains(err.Error(), "usage: diag ping") {
		t.Fatalf("expected usage error for empty ping args, got %v", err)
	}
	host, count, err := parseDiagPingArgs([]string{"example.test", "3"})
	if err != nil || host != "example.test" || count != 3 {
		t.Fatalf("unexpected ping parse: host=%q count=%d err=%v", host, count, err)
	}
	host, count, err = parseDiagPingArgs([]string{"example.test", "999"})
	if err != nil || host != "example.test" || count != 4 {
		t.Fatalf("expected ping count fallback to 4, got host=%q count=%d err=%v", host, count, err)
	}

	var out bytes.Buffer
	printDiagPingReply(&out, 1, &net.IPAddr{IP: net.ParseIP("192.0.2.10")}, ipv4.ICMPTypeEchoReply, 12*time.Millisecond)
	printDiagPingReply(&out, 2, &net.IPAddr{IP: net.ParseIP("192.0.2.11")}, ipv4.ICMPTypeDestinationUnreachable, 25*time.Millisecond)
	if err := printDiagPingSummary(&out, nil); err != nil {
		t.Fatalf("printDiagPingSummary(no replies): %v", err)
	}
	if err := printDiagPingSummary(&out, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}); err != nil {
		t.Fatalf("printDiagPingSummary(with replies): %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "seq=1") || !strings.Contains(rendered, "type=destination unreachable") {
		// Fallback below handles exact String() differences across x/net versions.
		if !strings.Contains(rendered, "DestinationUnreachable") && !strings.Contains(rendered, "destination unreachable") {
			t.Fatalf("unexpected ping output:\n%s", rendered)
		}
	}
	if !strings.Contains(rendered, "no replies") || !strings.Contains(rendered, "min/avg/max") {
		t.Fatalf("expected summary output, got:\n%s", rendered)
	}
}

func TestConvertSigmaUsage(t *testing.T) {
	if err := convertSigma(context.Background(), &bytes.Buffer{}, nil); err == nil || !strings.Contains(err.Error(), "usage: convert sigma") {
		t.Fatalf("expected convert sigma usage error, got %v", err)
	}
}

func TestICMPV4DstAddr(t *testing.T) {
	ip := net.ParseIP("192.0.2.44")
	if got := icmpV4DstAddr(nil, ip, 1234); got.String() == "" {
		t.Fatalf("expected fallback dst addr, got %v", got)
	}
}
