// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestSessionInputIdleRefresh(t *testing.T) {
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	in := &sessionInput{chunks: make(chan []byte, 1), idle: ticks}
	refreshed := false
	in.refresh = func() {
		refreshed = true
		in.chunks <- []byte("show version\n")
	}
	var buf [32]byte
	n, err := in.Read(buf[:])
	if err != nil || !refreshed || string(buf[:n]) != "show version\n" {
		t.Fatalf("refresh lost input: %q %v refreshed=%v", buf[:n], err, refreshed)
	}
}

func TestTerminalProgressPreservesPartialInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("show versx\bion\n"))
	var output strings.Builder
	partial := false
	line, ok := readTerminalLineProgress(reader, &output, true, func(nonempty bool) {
		partial = partial || nonempty
	})
	if !ok || !partial || line != "show version" {
		t.Fatalf("partial input lost: line=%q ok=%v partial=%v", line, ok, partial)
	}
}
