// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// auditCursorPrefix namespaces syslog forwarder cursors in the audit database.
const auditCursorPrefix = "syslog:"

const (
	syslogDialTimeout  = 2 * time.Second
	syslogWriteTimeout = 2 * time.Second
	syslogSendAttempts = 3
	auditCursorTimeout = 5 * time.Second
)

// syslogTarget is one distinct forwarder destination. Its id names the audit
// cursor, so a forwarder keeps its cursor while its proto, address and port
// stay the same.
type syslogTarget struct {
	id      string
	network string
	addr    string
}

func (t syslogTarget) cursor() string { return auditCursorPrefix + t.id }

// syslogTargets returns the configured destinations once each, in order.
func syslogTargets(fwds []config.SyslogForwarder) []syslogTarget {
	seen := make(map[string]bool, len(fwds))
	out := make([]syslogTarget, 0, len(fwds))
	for _, f := range fwds {
		network := strings.ToLower(strings.TrimSpace(f.Proto))
		if network == "" {
			network = "udp"
		}
		addr := net.JoinHostPort(f.Address, fmt.Sprint(firstNonZero(f.Port, 514)))
		t := syslogTarget{id: network + "://" + addr, network: network, addr: addr}
		if seen[t.id] {
			continue
		}
		seen[t.id] = true
		out = append(out, t)
	}
	return out
}

// auditForwarderStatus is the audit delivery state of one forwarder as of
// its last flush.
type auditForwarderStatus struct {
	lastID    int64
	backlog   int
	lastError string
	lastSent  time.Time
}

// SetAuditLog makes every forwarder also deliver audit records, oldest first,
// with a cursor per forwarder kept in the audit database.
func (m *SyslogManager) SetAuditLog(log audit.ForwardLog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopForwarder()
	m.auditLog = log
	m.syncAuditCursors()
	m.restartForwarder()
}

// syncAuditCursors starts a cursor at the newest record for each new
// forwarder and drops the cursors of removed forwarders. Before the first
// Apply the forwarder set is unknown, so nothing changes. Callers hold m.mu
// and have stopped the forwarder loop, so no flush recreates a dropped cursor.
func (m *SyslogManager) syncAuditCursors() {
	if m.auditLog == nil || !m.applied {
		return
	}
	targets := syslogTargets(m.config.Forwarders)
	keep := make([]string, 0, len(targets))
	ctx, cancel := context.WithTimeout(context.Background(), auditCursorTimeout)
	defer cancel()
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	var errs []string
	for _, t := range targets {
		keep = append(keep, t.cursor())
		if err := m.auditLog.StartForwardCursor(ctx, t.cursor()); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := m.auditLog.RetainForwardCursors(ctx, auditCursorPrefix, keep); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		m.auditLastError = strings.Join(errs, "; ")
		m.log.Errorw("syslog audit cursor sync failed", "error", m.auditLastError)
	}
}

// flushAudit sends each forwarder the audit records after its cursor, oldest
// first, and advances the cursor past the records it delivered. A failed send
// stops that forwarder's batch; the next tick retries from the cursor.
func (m *SyslogManager) flushAudit(ctx context.Context) {
	m.mu.Lock()
	log := m.auditLog
	targets := syslogTargets(m.config.Forwarders)
	format := m.config.Format
	batch := m.batchSize
	host := syslogHostname(m.hostname)
	m.mu.Unlock()
	if log == nil || len(targets) == 0 {
		return
	}
	if batch <= 0 {
		batch = 500
	}

	m.auditMu.Lock()
	if ctx.Err() != nil {
		m.auditMu.Unlock()
		return
	}
	results := make(map[string]auditForwarderStatus, len(targets))
	sent := make(map[string]int, len(targets))
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		st, n := m.forwardAudit(ctx, log, t, format, host, batch)
		results[t.id], sent[t.id] = st, n
	}
	m.auditMu.Unlock()
	if ctx.Err() != nil {
		// The loop was replaced or stopped mid-flush. Progress is persisted;
		// the next loop reports status for the current forwarders.
		return
	}

	now := time.Now().UTC()
	m.mu.Lock()
	for _, t := range targets {
		st := results[t.id]
		if sent[t.id] > 0 {
			st.lastSent = now
		} else {
			st.lastSent = m.auditForwarders[t.id].lastSent
		}
		results[t.id] = st
		m.auditSentTotal += sent[t.id]
		if st.lastError != "" {
			m.auditFailTotal++
			m.auditLastError = st.lastError
		}
	}
	m.auditForwarders = results
	m.auditLastFlush = now
	m.mu.Unlock()

	for _, t := range targets {
		if err := results[t.id].lastError; err != "" {
			m.log.Errorw("syslog audit forward failed", "forwarder", t.id, "error", err)
			m.emit("service.syslog.audit_forward_failed", map[string]any{"error": err, "forwarder": t.id, "error_count": 1})
		}
		if sent[t.id] > 0 {
			m.emit("service.syslog.audit_forward_ok", map[string]any{"forwarder": t.id, "count": sent[t.id]})
		}
	}
}

// forwardAudit delivers one batch to one forwarder. Callers hold m.auditMu.
func (m *SyslogManager) forwardAudit(ctx context.Context, log audit.ForwardLog, t syslogTarget, format, host string, batch int) (auditForwarderStatus, int) {
	var st auditForwarderStatus
	cursor, ok, err := log.ForwardCursor(ctx, t.cursor())
	if err == nil && !ok {
		// The cursor could not be started when the forwarder was configured.
		if err = log.StartForwardCursor(ctx, t.cursor()); err == nil {
			cursor, _, err = log.ForwardCursor(ctx, t.cursor())
		}
	}
	if err != nil {
		st.lastError = err.Error()
		return st, 0
	}
	recs, err := log.ListAfter(ctx, cursor, batch)
	if err != nil {
		st.lastID, st.lastError = cursor, err.Error()
		return st, 0
	}
	conn := &syslogConn{network: t.network, addr: t.addr}
	defer conn.close()
	last := cursor
	sent := 0
	for _, r := range recs {
		if err := conn.send(ctx, formatAudit(r, format, host)); err != nil {
			st.lastError = err.Error()
			break
		}
		last = r.ID
		sent++
	}
	// Persist progress even when the loop is stopping: records already sent
	// must not be counted as pending.
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditCursorTimeout)
	defer cancel()
	if last > cursor {
		if err := log.AdvanceForwardCursor(persistCtx, t.cursor(), last); err != nil {
			st.lastError = err.Error()
		}
	}
	st.lastID = last
	if st.backlog, err = log.CountAfter(persistCtx, last); err != nil && st.lastError == "" {
		st.lastError = err.Error()
	}
	return st, sent
}

// auditStatus reports audit forwarding next to the event counters. Callers
// hold m.mu.
func (m *SyslogManager) auditStatus() map[string]any {
	forwarders := make([]map[string]any, 0, len(m.auditForwarders))
	backlog := 0
	for _, t := range syslogTargets(m.config.Forwarders) {
		st, ok := m.auditForwarders[t.id]
		if !ok {
			continue
		}
		backlog += st.backlog
		forwarders = append(forwarders, map[string]any{
			"forwarder":  t.id,
			"last_id":    st.lastID,
			"backlog":    st.backlog,
			"last_error": st.lastError,
			"last_sent":  formatTime(st.lastSent),
		})
	}
	return map[string]any{
		"enabled":      m.auditLog != nil,
		"sent_total":   m.auditSentTotal,
		"failed_total": m.auditFailTotal,
		"last_error":   m.auditLastError,
		"last_flush":   formatTime(m.auditLastFlush),
		"backlog":      backlog,
		"forwarders":   forwarders,
	}
}

// syslogConn sends newline-framed messages to one forwarder over a single
// connection, redialling after a failed write. TCP delivery means the local
// stack accepted the bytes; UDP has no delivery signal.
type syslogConn struct {
	network string
	addr    string
	conn    net.Conn
}

func (c *syslogConn) send(ctx context.Context, payload string) error {
	msg := append([]byte(payload), '\n')
	var lastErr error
	for attempt := range syslogSendAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
		if c.conn == nil {
			d := net.Dialer{Timeout: syslogDialTimeout}
			conn, err := d.DialContext(ctx, c.network, c.addr)
			if err != nil {
				lastErr = err
				continue
			}
			c.conn = conn
		}
		_ = c.conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout))
		if _, err := c.conn.Write(msg); err != nil {
			lastErr = err
			c.close()
			continue
		}
		return nil
	}
	return lastErr
}

func (c *syslogConn) close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
