// SPDX-License-Identifier: Apache-2.0
package services

import (
	"io"
	"strings"
	"sync"
)

// OpenVPN's foreground console readiness marker is emitted only after its
// initialization has completed. Preserve logging without retaining an unbounded
// daemon log in memory. Stdout and stderr may write concurrently.
type openVPNReadyWriter struct {
	mu    sync.Mutex
	out   io.Writer
	tail  string
	ready chan struct{}
	once  sync.Once
	up    bool
}

func newOpenVPNReadyWriter(out io.Writer) *openVPNReadyWriter {
	return &openVPNReadyWriter{out: out, ready: make(chan struct{})}
}
func (w *openVPNReadyWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.out.Write(b)
	text := w.tail + string(b)
	initialized := strings.LastIndex(text, "Initialization Sequence Completed")
	restarting := strings.LastIndex(text, "SIGUSR1[")
	if initialized >= 0 {
		w.once.Do(func() { close(w.ready) })
	}
	if initialized >= 0 || restarting >= 0 {
		w.up = initialized > restarting
	}
	if len(text) > 64 {
		text = text[len(text)-64:]
	}
	w.tail = text
	return n, err
}

// connected distinguishes a live retrying client from a completed tunnel.
// OpenVPN emits SIGUSR1 when a soft restart drops the connection.
func (w *openVPNReadyWriter) connected() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.up
}
