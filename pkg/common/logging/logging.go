package logging

import (
	"os"
	"strings"
	"time"

	"github.com/RackSec/srslog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Options control logger construction and sinks.
type Options struct {
	Level          string
	FilePath       string
	MaxSizeMB      int
	MaxBackups     int
	MaxAgeDays     int
	JSON           bool
	SyslogAddr     string // host:port or unix socket path
	SyslogProtocol string // udp|tcp|unix
}

// NewZap returns a sugared zap logger with stdout and optional rotating file sink.
func NewZap(service, facility string, opts Options) (*zap.SugaredLogger, error) {
	// Global and per-service env overrides for level (e.g., CONTAIND_LOG_LEVEL=debug or CONTAIND_LOG_LEVEL_PROXY=warn).
	levelEnv := strings.TrimSpace(os.Getenv("CONTAIND_LOG_LEVEL"))
	if svcLevel := strings.TrimSpace(os.Getenv("CONTAIND_LOG_LEVEL_" + strings.ToUpper(service))); svcLevel != "" {
		levelEnv = svcLevel
	}
	if levelEnv != "" && opts.Level == "" {
		opts.Level = levelEnv
	}
	disableFile := strings.TrimSpace(os.Getenv("CONTAIND_LOG_FILE"))
	if disableFile == "0" || strings.EqualFold(disableFile, "false") || strings.EqualFold(disableFile, "off") {
		opts.FilePath = ""
	}
	if strings.TrimSpace(opts.SyslogAddr) == "" {
		if envAddr := strings.TrimSpace(os.Getenv("CONTAIND_LOG_SYSLOG_ADDR")); envAddr != "" {
			opts.SyslogAddr = envAddr
		}
	}
	if strings.TrimSpace(opts.SyslogProtocol) == "" {
		if envProto := strings.TrimSpace(os.Getenv("CONTAIND_LOG_SYSLOG_PROTO")); envProto != "" {
			opts.SyslogProtocol = envProto
		}
	}

	if opts.MaxSizeMB == 0 {
		opts.MaxSizeMB = 20
	}
	if opts.MaxBackups == 0 {
		opts.MaxBackups = 5
	}
	if opts.MaxAgeDays == 0 {
		opts.MaxAgeDays = 7
	}
	// Syslog sink is intentionally omitted until we add a portable client.
	cores := []zapcore.Core{}

	level := zapcore.InfoLevel
	if err := level.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(opts.Level)))); err != nil {
		level = zapcore.InfoLevel
	}

	encCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stack",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout(time.RFC3339Nano),
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	stdoutEnc := zapcore.NewConsoleEncoder(encCfg)
	if opts.JSON {
		stdoutEnc = zapcore.NewJSONEncoder(encCfg)
	}
	cores = append(cores, zapcore.NewCore(stdoutEnc, zapcore.AddSync(os.Stdout), level))

	if strings.TrimSpace(opts.FilePath) != "" {
		lj := &lumberjack.Logger{
			Filename:   opts.FilePath,
			MaxSize:    opts.MaxSizeMB,
			MaxBackups: opts.MaxBackups,
			MaxAge:     opts.MaxAgeDays,
			Compress:   false,
		}
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(lj), level))
	}

	if strings.TrimSpace(opts.SyslogAddr) != "" {
		proto := strings.TrimSpace(opts.SyslogProtocol)
		if proto == "" {
			proto = "udp"
		}
		fac := parseFacility(facility)
		writer, err := srslog.Dial(proto, opts.SyslogAddr, fac, service)
		if err != nil {
			return nil, err
		}
		writer.SetFormatter(srslog.RFC5424Formatter)
		cores = append(cores, zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(writer), level))
	}

	logger := zap.New(zapcore.NewTee(cores...)).With(
		zap.String("service", service),
		zap.String("facility", facility),
	)
	return logger.Sugar(), nil
}

func parseFacility(f string) srslog.Priority {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "kern":
		return srslog.LOG_KERN
	case "user":
		return srslog.LOG_USER
	case "mail":
		return srslog.LOG_MAIL
	case "daemon":
		return srslog.LOG_DAEMON
	case "auth", "authpriv":
		return srslog.LOG_AUTH
	case "syslog":
		return srslog.LOG_SYSLOG
	case "lpr":
		return srslog.LOG_LPR
	case "news":
		return srslog.LOG_NEWS
	case "uucp":
		return srslog.LOG_UUCP
	case "cron":
		return srslog.LOG_CRON
	case "ftp":
		return srslog.LOG_FTP
	case "local0":
		return srslog.LOG_LOCAL0
	case "local1":
		return srslog.LOG_LOCAL1
	case "local2":
		return srslog.LOG_LOCAL2
	case "local3":
		return srslog.LOG_LOCAL3
	case "local4":
		return srslog.LOG_LOCAL4
	case "local5":
		return srslog.LOG_LOCAL5
	case "local6":
		return srslog.LOG_LOCAL6
	case "local7":
		return srslog.LOG_LOCAL7
	default:
		return srslog.LOG_DAEMON
	}
}
