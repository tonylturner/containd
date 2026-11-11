// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

func TestAuditSourceIsServerAssignedAndForwarded(t *testing.T) {
	t.Setenv("CONTAIND_LOG_FILE", "off")
	store, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for syslog: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	manager := cpservices.NewSyslogManager()
	manager.SetAuditLog(store)
	t.Cleanup(manager.Stop)
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := manager.Apply(context.Background(), config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{{Address: "127.0.0.1", Port: port, Proto: "udp"}},
		Format:     "json",
		FlushEvery: 1,
	}); err != nil {
		t.Fatalf("apply syslog config: %v", err)
	}

	router := gin.New()
	router.Use(withAuditStore(store))
	router.POST("/", func(c *gin.Context) {
		auditLog(c, audit.Record{Action: "audit.test", Target: "request"})
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("X-Source", "forged")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("request status = %d, want %d", response.Code, http.StatusNoContent)
	}

	records, err := store.List(context.Background(), 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("stored audit records = %+v, error = %v", records, err)
	}
	if records[0].Source != "api" {
		t.Fatalf("stored audit source = %q, want api", records[0].Source)
	}

	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set syslog deadline: %v", err)
	}
	message := make([]byte, 4096)
	n, _, err := listener.ReadFrom(message)
	if err != nil {
		t.Fatalf("read forwarded audit record: %v", err)
	}
	var forwarded struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(message[:n], &forwarded); err != nil {
		t.Fatalf("decode forwarded audit record %q: %v", message[:n], err)
	}
	if forwarded.Source != records[0].Source {
		t.Fatalf("forwarded audit source = %q, want stored source %q", forwarded.Source, records[0].Source)
	}
}
