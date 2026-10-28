// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// stopAfterWrite models a final response arriving while an upload Write
// is returning. Its bytes reached the origin before stop was closed.
type stopAfterWrite struct {
	bytes.Buffer
	stop   chan struct{}
	writes int
}

func (w *stopAfterWrite) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.writes--
	if w.writes == 0 {
		close(w.stop)
	}
	return n, err
}

func TestWriteBodyStopAfterWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    bodyKind
		held    int
		excess  bool
		rest    bool
		stopped bool
		writes  int
	}{
		{name: "complete-held", kind: bodyLength, held: 1000},
		{name: "complete-streamed", kind: bodyLength, rest: true},
		{name: "held-remainder", kind: bodyLength, held: copyBufSize + 1, stopped: true},
		{name: "excess-remains", kind: bodyLength, held: 1000, excess: true, stopped: true},
		{name: "stream-remains", kind: bodyLength, held: 1000, rest: true, stopped: true},
		{name: "terminator-remains", kind: bodyChunked, held: 1000, stopped: true},
		{name: "complete-chunked", kind: bodyChunked, held: 1000, writes: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := newSpool(t.TempDir(), headCap)
			defer sp.close()
			body := bytes.Repeat([]byte("a"), tc.held)
			if _, err := sp.Write(body); err != nil {
				t.Fatal(err)
			}
			src := bodySource{kind: tc.kind}
			if tc.held > 0 {
				src.held = sp
			}
			if tc.excess {
				src.excess = []byte("excess")
			}
			if tc.rest {
				src.rest = bytes.NewReader([]byte("rest"))
			}
			w := &stopAfterWrite{stop: make(chan struct{}), writes: max(tc.writes, 1)}
			n, err := writeBody(newBodyWriter(w, tc.kind), src, w.stop)
			if tc.stopped {
				if !errors.Is(err, errStopped) {
					t.Fatalf("error %v, want forwarding stopped", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := body[:min(len(body), copyBufSize)]
			if tc.held == 0 {
				want = []byte("rest")
			}
			wire := want
			if tc.kind == bodyChunked {
				// Include the terminator only when its write completed.
				wire = fmt.Appendf(nil, "%x\r\n%s\r\n", len(want), want)
				if !tc.stopped {
					wire = append(wire, "0\r\n\r\n"...)
				}
			}
			if n != int64(len(want)) || !bytes.Equal(w.Bytes(), wire) {
				t.Fatalf("forwarded %d body bytes, %d wire bytes; want %d, %d", n, w.Len(), len(want), len(wire))
			}
		})
	}
}
