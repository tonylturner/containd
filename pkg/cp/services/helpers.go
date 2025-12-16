package services

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

func detectBinary(candidates []string) (string, bool) {
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func firstNonZero(v int, def int) int {
	if v != 0 {
		return v
	}
	return def
}

func formatMaybe(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func pidOrZero(cmd *exec.Cmd) int {
	if cmd == nil || cmd.Process == nil {
		return 0
	}
	return cmd.Process.Pid
}
