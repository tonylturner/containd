// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package logging

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapHandler implements slog.Handler by delegating to a zap.Logger.
type zapHandler struct {
	logger *zap.Logger
	group  string
	attrs  []zap.Field
}

func (h *zapHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.logger.Core().Enabled(slogToZapLevel(level))
}

func (h *zapHandler) Handle(_ context.Context, r slog.Record) error {
	fields := make([]zap.Field, 0, len(h.attrs)+r.NumAttrs())
	fields = append(fields, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		fields = append(fields, slogAttrToZapField(h.group, a))
		return true
	})
	ce := h.logger.Check(slogToZapLevel(r.Level), r.Message)
	if ce != nil {
		ce.Write(fields...)
	}
	return nil
}

func (h *zapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	fields := make([]zap.Field, 0, len(h.attrs)+len(attrs))
	fields = append(fields, h.attrs...)
	for _, a := range attrs {
		fields = append(fields, slogAttrToZapField(h.group, a))
	}
	return &zapHandler{logger: h.logger, group: h.group, attrs: fields}
}

func (h *zapHandler) WithGroup(name string) slog.Handler {
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &zapHandler{logger: h.logger, group: g, attrs: append([]zap.Field{}, h.attrs...)}
}

func slogToZapLevel(l slog.Level) zapcore.Level {
	switch {
	case l >= slog.LevelError:
		return zapcore.ErrorLevel
	case l >= slog.LevelWarn:
		return zapcore.WarnLevel
	case l >= slog.LevelInfo:
		return zapcore.InfoLevel
	default:
		return zapcore.DebugLevel
	}
}

func slogAttrToZapField(group string, a slog.Attr) zap.Field {
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	return zap.Any(key, a.Value.Any())
}

// InstallSlogBridge sets the default slog logger to route through the given
// zap logger. This ensures all slog.Info/Warn/Error calls go through zap's
// sinks including syslog forwarding.
func InstallSlogBridge(logger *zap.Logger) {
	slog.SetDefault(slog.New(&zapHandler{logger: logger}))
}

// SetupGlobalLogger creates a named zap service logger, installs the slog bridge,
// and redirects stdlib log output through zap. Call this early in main().
func SetupGlobalLogger(service string) *zap.SugaredLogger {
	sugar := NewService(service)
	logger := sugar.Desugar()
	InstallSlogBridge(logger)
	// Redirect stdlib log to zap as well.
	zap.RedirectStdLog(logger)
	return sugar
}
