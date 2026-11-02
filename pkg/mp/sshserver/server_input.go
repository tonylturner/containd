// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"io"
	"sync"
)

// sessionInput reads one SSH channel in a single goroutine, so the appliance
// CLI and a Linux shell it starts can take turns without losing input. A
// read that is blocked when the shell exits would otherwise consume the
// CLI's next line.
type sessionInput struct {
	chunks  chan []byte
	done    chan struct{}
	stop    sync.Once
	err     error  // the channel's read error; set before chunks closes
	pending []byte // the rest of a chunk Read has taken
	status  <-chan struct{}
	refresh func()
}

func newSessionInput(r io.Reader) *sessionInput {
	in := &sessionInput{chunks: make(chan []byte), done: make(chan struct{})}
	go in.pump(r)
	return in
}

func (in *sessionInput) pump(r io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			select {
			case in.chunks <- chunk:
			case <-in.done:
				return
			}
		}
		if err != nil {
			in.err = err
			close(in.chunks)
			return
		}
	}
}

// Read returns input for the CLI.
func (in *sessionInput) Read(p []byte) (int, error) {
	if len(in.pending) == 0 {
		for len(in.pending) == 0 {
			select {
			case chunk, ok := <-in.chunks:
				if !ok {
					return 0, in.err
				}
				in.pending = chunk
			case <-in.status:
				if in.refresh != nil {
					in.refresh()
				}
			}
		}
	}
	n := copy(p, in.pending)
	in.pending = in.pending[n:]
	return n, nil
}

// forward writes input to w until stop closes or w fails. Input forward has
// not taken stays for the next Read.
func (in *sessionInput) forward(w io.Writer, stop <-chan struct{}) {
	if len(in.pending) > 0 {
		chunk := in.pending
		in.pending = nil
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
	for {
		select {
		case <-stop:
			return
		case chunk, ok := <-in.chunks:
			if !ok {
				return
			}
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}
}

// close stops the pump once the session no longer reads input.
func (in *sessionInput) close() {
	in.stop.Do(func() { close(in.done) })
}

// sessionIO is the appliance CLI's terminal: input shared with any Linux
// shell it starts, and the channel for output.
type sessionIO struct {
	*sessionInput
	io.Writer
}
