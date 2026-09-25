// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"errors"
	"strings"
	"testing"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/tonylturner/containd/pkg/dp/events"
)

type fakeNFLogHandle struct {
	ctx               context.Context
	registerErr       error
	errFn             nflog.ErrorFunc
	closeCalls        int
	closeBeforeCancel bool
}

func (f *fakeNFLogHandle) RegisterWithErrorFunc(ctx context.Context, _ nflog.HookFunc, errFn nflog.ErrorFunc) error {
	f.ctx = ctx
	f.errFn = errFn
	return f.registerErr
}

func (f *fakeNFLogHandle) Close() error {
	f.closeCalls++
	if f.ctx == nil || f.ctx.Err() == nil {
		f.closeBeforeCancel = true
		return errors.New("Close called before context cancellation")
	}
	return nil
}

func TestStartNFLogStopCancelsBeforeClosingAndIsIdempotent(t *testing.T) {
	oldOpenNFLog := openNFLog
	t.Cleanup(func() { openNFLog = oldOpenNFLog })
	fake := &fakeNFLogHandle{}
	openNFLog = func(*nflog.Config) (nfLogHandle, error) { return fake, nil }

	var reported int
	stop, err := StartNFLog(context.Background(), 100, events.NewStore(1), func(error) { reported++ })
	if err != nil {
		t.Fatalf("StartNFLog: %v", err)
	}
	if stop == nil {
		t.Fatal("StartNFLog returned nil stop function")
	}
	if fake.ctx == nil || fake.ctx.Err() != nil {
		t.Fatalf("registration context before stop = %v, want active child context", fake.ctx)
	}
	stop()
	if fake.ctx.Err() != context.Canceled {
		t.Fatalf("registration context after stop = %v, want canceled", fake.ctx.Err())
	}
	if fake.closeCalls != 1 {
		t.Fatalf("Close calls after first stop = %d, want 1", fake.closeCalls)
	}
	if fake.closeBeforeCancel {
		t.Fatal("Close ran before cancellation")
	}
	stop()
	if fake.closeCalls != 1 {
		t.Fatalf("Close calls after second stop = %d, want 1", fake.closeCalls)
	}
	if got := fake.errFn(errors.New("closed")); got != 1 {
		t.Fatalf("error callback return after cancellation = %d, want 1", got)
	}
	if reported != 1 {
		t.Fatalf("onErr calls = %d, want 1", reported)
	}
}

func TestStartNFLogRegisterErrorCancelsAndCloses(t *testing.T) {
	oldOpenNFLog := openNFLog
	t.Cleanup(func() { openNFLog = oldOpenNFLog })
	wantErr := errors.New("register failed")
	fake := &fakeNFLogHandle{registerErr: wantErr}
	openNFLog = func(*nflog.Config) (nfLogHandle, error) { return fake, nil }

	stop, err := StartNFLog(context.Background(), 100, events.NewStore(1), nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("StartNFLog error = %v, want wrapped %v", err, wantErr)
	}
	if stop == nil {
		t.Fatal("StartNFLog returned nil stop function on registration error")
	}
	if fake.ctx == nil || fake.ctx.Err() != context.Canceled {
		t.Fatalf("registration context after error = %v, want canceled", fake.ctx)
	}
	if fake.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", fake.closeCalls)
	}
	if fake.closeBeforeCancel {
		t.Fatal("registration failure cleanup closed before cancellation")
	}
	stop()
	if fake.closeCalls != 1 {
		t.Fatalf("no-op stop Close calls = %d, want 1", fake.closeCalls)
	}
}

func TestStartNFLogDisabledReturnsNoOpStop(t *testing.T) {
	oldOpenNFLog := openNFLog
	t.Cleanup(func() { openNFLog = oldOpenNFLog })
	var opens int
	openNFLog = func(*nflog.Config) (nfLogHandle, error) {
		opens++
		return &fakeNFLogHandle{}, nil
	}
	for _, tc := range []struct {
		name  string
		group uint16
		sink  RuleHitSink
	}{
		{name: "zero group", group: 0, sink: events.NewStore(1)},
		{name: "nil sink", group: 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop, err := StartNFLog(context.Background(), tc.group, tc.sink, nil)
			if err != nil {
				t.Fatalf("StartNFLog: %v", err)
			}
			if stop == nil {
				t.Fatal("StartNFLog returned nil stop function")
			}
			stop()
		})
	}
	if opens != 0 {
		t.Fatalf("openNFLog calls = %d, want 0", opens)
	}
}

// strPtr is a small helper to build nflog.Attribute.Prefix (which is a
// *string in the upstream API).
func strPtr(s string) *string { return &s }

// bytesPtr is a small helper to build nflog.Attribute.Payload (which is
// a *[]byte in the upstream API).
func bytesPtr(b []byte) *[]byte { return &b }

func TestBuildRuleHitEventParsesPrefix(t *testing.T) {
	a := nflog.Attribute{
		Prefix: strPtr("containd:deny-ent-to-field:DENY "),
	}
	ev, ok := buildRuleHitEvent(a)
	if !ok {
		t.Fatal("expected event, got !ok")
	}
	if ev.Kind != "firewall.rule.hit" {
		t.Errorf("Kind = %q, want firewall.rule.hit", ev.Kind)
	}
	if got, want := ev.Attributes["ruleId"], "deny-ent-to-field"; got != want {
		t.Errorf("ruleId = %v, want %q", got, want)
	}
	if got, want := ev.Attributes["action"], "DENY"; got != want {
		t.Errorf("action = %v, want %q", got, want)
	}
	if got, want := ev.Attributes["via"], "nflog"; got != want {
		t.Errorf("via = %v, want %q", got, want)
	}
}

func TestBuildRuleHitEventRejectsForeignPrefix(t *testing.T) {
	cases := []string{
		"some other kernel log message",
		"containd:",
		"containd:rule:lowercase",
		"",
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			a := nflog.Attribute{Prefix: strPtr(c)}
			if _, ok := buildRuleHitEvent(a); ok {
				t.Errorf("expected !ok for prefix %q", c)
			}
		})
	}
}

func TestBuildRuleHitEventNoPrefixIsNoop(t *testing.T) {
	a := nflog.Attribute{} // Prefix nil
	if _, ok := buildRuleHitEvent(a); ok {
		t.Error("expected !ok when no prefix is set")
	}
}

func TestBuildRuleHitEventExtractsPacketFields(t *testing.T) {
	// Minimal IPv4+TCP packet: src 10.10.10.50 -> dst 10.40.40.20:502.
	// 20-byte IPv4 header (no options) + 20-byte TCP header, no payload.
	pkt := []byte{
		// IPv4 header
		0x45,       // version=4, ihl=5
		0x00,       // dscp+ecn
		0x00, 0x28, // total length = 40
		0x00, 0x00, // identification
		0x40, 0x00, // flags + fragment offset
		0x40,       // ttl
		0x06,       // protocol = TCP
		0x00, 0x00, // header checksum (zero, not validated)
		10, 10, 10, 50, // src 10.10.10.50
		10, 40, 40, 20, // dst 10.40.40.20
		// TCP header (20 bytes)
		0xc0, 0x00, // src port 49152
		0x01, 0xf6, // dst port 502 (Modbus)
		0x00, 0x00, 0x00, 0x00, // seq
		0x00, 0x00, 0x00, 0x00, // ack
		0x50, 0x02, // data offset 5, SYN flag
		0x20, 0x00, // window
		0x00, 0x00, // checksum
		0x00, 0x00, // urgent
	}
	a := nflog.Attribute{
		Prefix:  strPtr("containd:fw-test:DENY "),
		Payload: bytesPtr(pkt),
	}
	ev, ok := buildRuleHitEvent(a)
	if !ok {
		t.Fatal("expected event, got !ok")
	}
	if ev.SrcIP != "10.10.10.50" {
		t.Errorf("SrcIP = %q, want 10.10.10.50", ev.SrcIP)
	}
	if ev.DstIP != "10.40.40.20" {
		t.Errorf("DstIP = %q, want 10.40.40.20", ev.DstIP)
	}
	if ev.SrcPort != 49152 {
		t.Errorf("SrcPort = %d, want 49152", ev.SrcPort)
	}
	if ev.DstPort != 502 {
		t.Errorf("DstPort = %d, want 502", ev.DstPort)
	}
	if ev.Transport != "tcp" {
		t.Errorf("Transport = %q, want tcp", ev.Transport)
	}
	if ev.Attributes["proto"] != "tcp" {
		t.Errorf("proto attribute = %v, want tcp", ev.Attributes["proto"])
	}
	if ev.Attributes["port"] != "502" {
		t.Errorf("port attribute = %v, want \"502\"", ev.Attributes["port"])
	}
}

func TestRulePrefixREAcceptsTypicalForms(t *testing.T) {
	cases := []struct {
		prefix string
		id     string
		action string
	}{
		{"containd:foo:ALLOW ", "foo", "ALLOW"},
		{"containd:deny-enterprise-to-field:DENY ", "deny-enterprise-to-field", "DENY"},
		{"containd:rtac-to-field-modbus:ALLOW", "rtac-to-field-modbus", "ALLOW"},
		{"containd:underscores_ok_too:ALLOW ", "underscores_ok_too", "ALLOW"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.prefix, func(t *testing.T) {
			m := rulePrefixRE.FindStringSubmatch(strings.TrimSpace(c.prefix))
			if m == nil {
				t.Fatalf("expected match for %q", c.prefix)
			}
			if m[1] != c.id || m[2] != c.action {
				t.Errorf("got (%q, %q), want (%q, %q)", m[1], m[2], c.id, c.action)
			}
		})
	}
}

func TestRulePrefixRERejectsUnsafeRuleIDs(t *testing.T) {
	// Producer side sanitizes — these prefixes shouldn't reach us in
	// practice. But if a packet's prefix is somehow malformed (bug,
	// foreign log message, manually-applied rule), we should drop the
	// packet rather than emit a garbage event with a broken ruleId.
	cases := []string{
		`containd:id with spaces:DENY `, // space breaks the ID match
		`containd::DENY `,               // empty ID
		`containd:id"q:DENY `,           // unescaped quote
		`containd:id/slash:DENY `,       // slash
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			a := nflog.Attribute{Prefix: strPtr(c)}
			if _, ok := buildRuleHitEvent(a); ok {
				t.Errorf("expected !ok for malformed prefix %q", c)
			}
		})
	}
}
