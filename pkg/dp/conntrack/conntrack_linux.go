// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// List reads the kernel conntrack table via /proc.
// It typically requires the container to have access to host conntrack namespace.
func List(limit int) ([]Entry, error) {
	path := "/proc/net/nf_conntrack"
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return []Entry{}, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stat conntrack table: %w", err)
		}
		// Fallback for older kernels.
		path = "/proc/net/ip_conntrack"
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return []Entry{}, nil
		}
		return nil, fmt.Errorf("open conntrack table: %w", err)
	}
	defer f.Close()

	out := []Entry{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		e := parseLine(line)
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read conntrack table: %w", err)
	}
	return out, nil
}

func parseLine(line string) Entry {
	e := Entry{Raw: line}
	parts := strings.Fields(line)
	parseConntrackHeader(&e, parts)
	parseConntrackFields(&e, parts)
	return e
}

func parseConntrackHeader(e *Entry, parts []string) {
	if len(parts) >= 3 {
		e.Proto = parts[2]
	}
	if len(parts) >= 5 {
		if v, err := strconv.Atoi(parts[4]); err == nil {
			e.TimeoutSecs = v
		}
	}
	if len(parts) >= 6 && strings.ToUpper(parts[5]) == parts[5] {
		e.State = parts[5]
	}
}

func parseConntrackFields(e *Entry, parts []string) {
	seen := conntrackFieldState{}
	for _, p := range parts {
		if p == "[ASSURED]" {
			e.Assured = true
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		assignConntrackField(e, &seen, k, v)
	}
}

type conntrackFieldState struct {
	src, dst, sport, dport int
}

func assignConntrackField(e *Entry, seen *conntrackFieldState, key, value string) {
	switch key {
	case "src":
		seen.src++
		assignConntrackEndpoint(&e.Src, &e.ReplySrc, seen.src, value)
	case "dst":
		seen.dst++
		assignConntrackEndpoint(&e.Dst, &e.ReplyDst, seen.dst, value)
	case "sport":
		seen.sport++
		assignConntrackEndpoint(&e.Sport, &e.ReplySport, seen.sport, value)
	case "dport":
		seen.dport++
		assignConntrackEndpoint(&e.Dport, &e.ReplyDport, seen.dport, value)
	case "mark":
		e.Mark = value
	}
}

func assignConntrackEndpoint(primary, reply *string, seen int, value string) {
	switch seen {
	case 1:
		*primary = value
	case 2:
		*reply = value
	}
}
