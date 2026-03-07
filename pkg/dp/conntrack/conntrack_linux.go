// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import (
	"bufio"
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
		// Fallback for older kernels.
		path = "/proc/net/ip_conntrack"
	}
	f, err := os.Open(path)
	if err != nil {
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
	if len(parts) >= 3 {
		e.Proto = parts[2]
	}
	// Timeout is usually parts[4].
	if len(parts) >= 5 {
		if v, err := strconv.Atoi(parts[4]); err == nil {
			e.TimeoutSecs = v
		}
	}
	// TCP state is typically right after timeout, e.g. parts[5].
	if len(parts) >= 6 && strings.ToUpper(parts[5]) == parts[5] {
		e.State = parts[5]
	}

	// Key/value pairs; src/dst/sport/dport appear twice (original + reply).
	sawSrc, sawDst, sawSport, sawDport := 0, 0, 0, 0
	for _, p := range parts {
		if p == "[ASSURED]" {
			e.Assured = true
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		switch k {
		case "src":
			sawSrc++
			if sawSrc == 1 {
				e.Src = v
			} else if sawSrc == 2 {
				e.ReplySrc = v
			}
		case "dst":
			sawDst++
			if sawDst == 1 {
				e.Dst = v
			} else if sawDst == 2 {
				e.ReplyDst = v
			}
		case "sport":
			sawSport++
			if sawSport == 1 {
				e.Sport = v
			} else if sawSport == 2 {
				e.ReplySport = v
			}
		case "dport":
			sawDport++
			if sawDport == 1 {
				e.Dport = v
			} else if sawDport == 2 {
				e.ReplyDport = v
			}
		case "mark":
			e.Mark = v
		}
	}
	return e
}

