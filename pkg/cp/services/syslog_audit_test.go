// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func openAuditStore(t *testing.T, path string) *audit.SQLiteStore {
	t.Helper()
	store, err := audit.NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	return store
}

func addAudit(t *testing.T, store *audit.SQLiteStore, recs ...audit.Record) {
	t.Helper()
	for _, r := range recs {
		if r.Result == "" {
			r.Result = "success"
		}
		if err := store.Add(context.Background(), r); err != nil {
			t.Fatalf("add audit record: %v", err)
		}
	}
}

func auditAction(action string) audit.Record {
	return audit.Record{Actor: "admin", Source: "api", Action: action, Target: "running"}
}

// newAuditSyslog returns a manager with the audit log installed and the
// given forwarders applied. With manual set, the forwarder loop is stopped
// and the test drives flushAudit itself.
func newAuditSyslog(t *testing.T, store audit.ForwardLog, cfg config.SyslogConfig, manual bool) *SyslogManager {
	t.Helper()
	mgr := NewSyslogManager()
	mgr.log = zap.NewNop().Sugar()
	mgr.hostname = "fw1"
	mgr.SetAuditLog(store)
	if err := mgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if manual {
		mgr.Stop()
	}
	t.Cleanup(mgr.Stop)
	return mgr
}

func forwarderConfig(format, proto string, port int) config.SyslogConfig {
	return config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{{Address: "127.0.0.1", Port: port, Proto: proto}},
		Format:     format,
		FlushEvery: 1,
	}
}

func listenUDPLines(t *testing.T) (int, <-chan string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	lines := make(chan string, 64)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			lines <- string(buf[:n])
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, lines
}

func listenTCPLines(t *testing.T, addr string) (net.Listener, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen(%s): %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	lines := make(chan string, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					lines <- sc.Text()
				}
			}()
		}
	}()
	return ln, lines
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func nextLine(t *testing.T, lines <-chan string) string {
	t.Helper()
	select {
	case l := <-lines:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a syslog line")
		return ""
	}
}

func auditIDs(t *testing.T, lines <-chan string, n int) []int64 {
	t.Helper()
	ids := make([]int64, 0, n)
	for range n {
		var msg struct {
			Kind string `json:"kind"`
			ID   int64  `json:"id"`
		}
		line := nextLine(t, lines)
		if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.Kind != "audit" {
			t.Fatalf("not a JSON audit message (%v): %s", err, line)
		}
		ids = append(ids, msg.ID)
	}
	return ids
}

func auditSyslogStatus(mgr *SyslogManager) map[string]any {
	return mgr.Status()["audit"].(map[string]any)
}

func TestAuditSyslogWireFormatsOverUDP(t *testing.T) {
	store := openAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close()
	port, lines := listenUDPLines(t)
	ctx := context.Background()

	mgr := newAuditSyslog(t, store, forwarderConfig("json", "udp", port), true)
	long := strings.Repeat("é", 1000) // 2000 bytes
	addAudit(t, store, audit.Record{Actor: "admin", Source: "ssh", Action: "cli.execute", Target: "show version\nforged", Result: "failure", Detail: long})
	mgr.flushAudit(ctx)

	datagram := nextLine(t, lines)
	if strings.Count(datagram, "\n") != 1 || !strings.HasSuffix(datagram, "\n") {
		t.Fatalf("JSON message is not one newline-terminated line: %q", datagram)
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(datagram), &msg); err != nil {
		t.Fatalf("JSON message: %v", err)
	}
	if msg["kind"] != "audit" || msg["host"] != "fw1" || msg["id"] != float64(1) || msg["actor"] != "admin" ||
		msg["source"] != "ssh" || msg["action"] != "cli.execute" || msg["target"] != "show version\nforged" || msg["result"] != "failure" {
		t.Fatalf("unexpected JSON audit message: %v", msg)
	}
	detail := msg["detail"].(string)
	if len(detail) > auditDetailLimit || !strings.HasSuffix(detail, "…") || !strings.HasPrefix(detail, "éé") {
		t.Fatalf("detail not bounded: %d bytes", len(detail))
	}

	// Same forwarder, RFC 5424: the cursor is kept across the format change.
	cfg := forwarderConfig("rfc5424", "udp", port)
	if err := mgr.Apply(ctx, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	mgr.Stop()
	addAudit(t, store,
		audit.Record{Actor: "admin", Source: "api", Action: "config.commit", Target: "running", Result: "success", Detail: "a\nb \"q\" ]\\"},
		audit.Record{Actor: "eve", Source: "api", Action: "auth.login", Target: "eve", Result: "denied", Detail: "invalid credentials"},
	)
	mgr.flushAudit(ctx)

	first := nextLine(t, lines)
	wantPrefix := "<109>1 "
	wantSD := ` fw1 containd - audit [audit@47450 id="2" actor="admin" source="api" action="config.commit" target="running" result="success" detail="a\nb \"q\" \]\\"] admin config.commit running: success` + "\n"
	if !strings.HasPrefix(first, wantPrefix) || !strings.HasSuffix(first, wantSD) {
		t.Fatalf("RFC 5424 audit message = %q", first)
	}
	if _, err := time.Parse(time.RFC3339, strings.Fields(first)[1]); err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	second := nextLine(t, lines)
	if !strings.HasPrefix(second, "<108>1 ") || !strings.Contains(second, ` id="3" actor="eve"`) {
		t.Fatalf("denied record = %q; want severity warning", second)
	}
	if st := auditSyslogStatus(mgr); st["sent_total"] != 3 || st["backlog"] != 0 {
		t.Fatalf("audit status = %v", st)
	}
}

func TestAuditSyslogDeliversBacklogAfterTCPOutage(t *testing.T) {
	store := openAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close()
	port := freeTCPPort(t)
	mgr := newAuditSyslog(t, store, forwarderConfig("json", "tcp", port), false)

	addAudit(t, store, auditAction("a"), auditAction("b"), auditAction("c"))
	waitFor(t, 10*time.Second, func() bool {
		st := auditSyslogStatus(mgr)
		fwds := st["forwarders"].([]map[string]any)
		return len(fwds) == 1 && fwds[0]["backlog"] == 3 && fwds[0]["last_error"] != "" && st["failed_total"].(int) > 0
	})
	if st := auditSyslogStatus(mgr); st["last_error"] == "" || st["sent_total"] != 0 {
		t.Fatalf("audit status during the outage = %v", st)
	}

	_, lines := listenTCPLines(t, fmt.Sprintf("127.0.0.1:%d", port))
	if got := auditIDs(t, lines, 3); got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("backlog delivered as %v; want [1 2 3]", got)
	}
	waitFor(t, 5*time.Second, func() bool {
		fwds := auditSyslogStatus(mgr)["forwarders"].([]map[string]any)
		return len(fwds) == 1 && fwds[0]["backlog"] == 0 && fwds[0]["last_error"] == "" && fwds[0]["last_id"] == int64(3)
	})
}

func TestAuditSyslogResumesFromCursorAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ln, lines := listenTCPLines(t, "127.0.0.1:0")
	cfg := forwarderConfig("json", "tcp", ln.Addr().(*net.TCPAddr).Port)
	ctx := context.Background()

	store := openAuditStore(t, path)
	mgr := newAuditSyslog(t, store, cfg, true)
	addAudit(t, store, auditAction("a"), auditAction("b"))
	mgr.flushAudit(ctx)
	if got := auditIDs(t, lines, 2); got[0] != 1 || got[1] != 2 {
		t.Fatalf("first run delivered %v", got)
	}
	// Written after the last flush, then the process stops.
	addAudit(t, store, auditAction("c"), auditAction("d"))
	mgr.Stop()
	store.Close()

	store = openAuditStore(t, path)
	defer store.Close()
	mgr = newAuditSyslog(t, store, cfg, true)
	mgr.flushAudit(ctx)
	if got := auditIDs(t, lines, 2); got[0] != 3 || got[1] != 4 {
		t.Fatalf("after restart delivered %v; want [3 4]", got)
	}
}

func TestAuditSyslogNewForwarderStartsAtTip(t *testing.T) {
	store := openAuditStore(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close()
	ctx := context.Background()
	addAudit(t, store, auditAction("a"), auditAction("b"), auditAction("c"))

	udpPort, udpLines := listenUDPLines(t)
	mgr := newAuditSyslog(t, store, forwarderConfig("json", "udp", udpPort), true)
	mgr.flushAudit(ctx)
	if st := auditSyslogStatus(mgr); st["sent_total"] != 0 || st["backlog"] != 0 {
		t.Fatalf("new forwarder sent history: %v", st)
	}
	addAudit(t, store, auditAction("d"))
	mgr.flushAudit(ctx)
	if got := auditIDs(t, udpLines, 1); got[0] != 4 {
		t.Fatalf("UDP forwarder delivered %v; want [4]", got)
	}

	// Replace the UDP forwarder with a TCP one: the new one starts at the
	// tip and the removed one's cursor is dropped.
	ln, tcpLines := listenTCPLines(t, "127.0.0.1:0")
	if err := mgr.Apply(ctx, forwarderConfig("json", "tcp", ln.Addr().(*net.TCPAddr).Port)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	mgr.Stop()
	udpCursor := auditCursorPrefix + fmt.Sprintf("udp://127.0.0.1:%d", udpPort)
	if _, ok, err := store.ForwardCursor(ctx, udpCursor); err != nil || ok {
		t.Fatalf("removed forwarder cursor kept: ok=%v err=%v", ok, err)
	}
	addAudit(t, store, auditAction("e"))
	mgr.flushAudit(ctx)
	if got := auditIDs(t, tcpLines, 1); got[0] != 5 {
		t.Fatalf("TCP forwarder delivered %v; want [5]", got)
	}
	select {
	case l := <-udpLines:
		t.Fatalf("removed UDP forwarder still received %q", l)
	default:
	}
}
