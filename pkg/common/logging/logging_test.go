// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package logging

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RackSec/srslog"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewZapHonorsEnvAndFileToggle(t *testing.T) {
	t.Setenv("CONTAIND_LOG_LEVEL_TESTSVC", "debug")
	t.Setenv("CONTAIND_LOG_FILE", "false")

	logPath := filepath.Join(t.TempDir(), "disabled.log")
	logger, err := NewZap("testsvc", "daemon", Options{FilePath: logPath})
	if err != nil {
		t.Fatalf("NewZap: %v", err)
	}
	if !logger.Desugar().Core().Enabled(zap.DebugLevel) {
		t.Fatal("expected debug level from service-specific env override")
	}
	logger.Debug("debug message")
	_ = logger.Desugar().Sync()
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("expected file logging to be disabled, stat err=%v", err)
	}
}

func TestNewZapWritesConfiguredFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "service.log")
	logger, err := NewZap("filesvc", "local0", Options{
		Level:    "info",
		FilePath: logPath,
		JSON:     true,
	})
	if err != nil {
		t.Fatalf("NewZap: %v", err)
	}
	logger.Infow("file logger", "count", 1)
	_ = logger.Desugar().Sync()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"msg":"file logger"`) || !strings.Contains(text, `"service":"filesvc"`) {
		t.Fatalf("unexpected log file contents: %s", text)
	}
}

func TestParseFacility(t *testing.T) {
	if parseFacility("kern") != srslog.LOG_KERN {
		t.Fatal("expected kern facility")
	}
	if parseFacility("local3") != srslog.LOG_LOCAL3 {
		t.Fatal("expected local3 facility")
	}
	if parseFacility("weird") != srslog.LOG_DAEMON {
		t.Fatal("expected unknown facilities to fall back to daemon")
	}
}

func TestZapHandlerAndSlogBridge(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	handler := &zapHandler{logger: logger}

	if !handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("expected info level to be enabled")
	}
	if err := handler.Handle(context.Background(), slog.NewRecord(time.Unix(0, 0), slog.LevelInfo, "base message", 0)); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	withAttrs := handler.WithAttrs([]slog.Attr{slog.String("asset", "plc-1")})
	grouped := withAttrs.WithGroup("diag")
	rec := slog.NewRecord(time.Unix(0, 0), slog.LevelWarn, "grouped message", 0)
	rec.AddAttrs(slog.String("status", "warning"))
	if err := grouped.Handle(context.Background(), rec); err != nil {
		t.Fatalf("grouped Handle: %v", err)
	}

	InstallSlogBridge(logger)
	slog.Info("bridge message", "proto", "modbus")

	entries := observed.AllUntimed()
	if len(entries) < 3 {
		t.Fatalf("expected observed slog entries, got %d", len(entries))
	}
	last := entries[len(entries)-1]
	if last.Message != "bridge message" {
		t.Fatalf("unexpected slog bridge message: %#v", last)
	}
}

func TestNewServiceAndSetupGlobalLogger(t *testing.T) {
	t.Setenv("CONTAIND_LOG_SYSLOG_ADDR", "127.0.0.1:1")
	t.Setenv("CONTAIND_LOG_SYSLOG_PROTO", "tcp")
	t.Setenv("CONTAIND_LOG_FILE", "false")

	logger := NewService("bridge")
	if logger == nil {
		t.Fatal("expected NewService logger")
	}
	sugar := SetupGlobalLogger("bridge")
	if sugar == nil {
		t.Fatal("expected SetupGlobalLogger logger")
	}
	slog.Info("global bridge test", "component", "audit")
}
