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
}

func newOpenVPNReadyWriter(out io.Writer) *openVPNReadyWriter {
	return &openVPNReadyWriter{out: out, ready: make(chan struct{})}
}
func (w *openVPNReadyWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.out.Write(b)
	text := w.tail + string(b)
	if strings.Contains(text, "Initialization Sequence Completed") {
		w.once.Do(func() { close(w.ready) })
	}
	if len(text) > 64 {
		text = text[len(text)-64:]
	}
	w.tail = text
	return n, err
}
