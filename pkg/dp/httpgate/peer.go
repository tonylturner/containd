// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// headCap bounds one request or response head, bufio buffer included,
	// so a single line longer than the cap fails with bufio.ErrBufferFull.
	headCap = 64 << 10
	// chunkLineCap bounds one chunk-size line.
	chunkLineCap = 4 << 10
	// maxInterim bounds the 1xx responses relayed per transaction.
	maxInterim = 16
	// copyBufSize is the unit of body streaming and re-chunking.
	copyBufSize = 32 << 10
)

var (
	errHeadTooLarge = errors.New("httpgate: head exceeds 64 KiB")
	errInterrupted  = &timeoutError{"read interrupted"}
)

// timeoutError satisfies net.Error with Timeout true.
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string   { return e.msg }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// peer is one TCP connection with a buffered reader whose every read and
// write carries the idle deadline, plus an optional object deadline while
// a body is being received.
type peer struct {
	conn net.Conn
	r    *bufio.Reader
	idle time.Duration
	// objectDeadline is the unix-nanosecond deadline of the head or body
	// being received; 0 when none. objectArmed records whether the last
	// read was bounded by it rather than by the idle deadline.
	// firstByteWindow, when non-zero, is the duration the object deadline
	// is set to once the next byte arrives.
	objectDeadline  atomic.Int64
	objectArmed     atomic.Bool
	firstByteWindow atomic.Int64
	// interrupt makes the next read fail at once instead of blocking; a
	// close watcher is stopped with it.
	interrupt atomic.Bool
	// active is set by the first byte read since it was last cleared; a
	// client peer that is not active awaits its next request.
	active    atomic.Bool
	closeOnce sync.Once
}

func newPeer(c net.Conn, idle time.Duration) *peer {
	p := &peer{conn: c, idle: idle}
	p.r = bufio.NewReaderSize((*peerReader)(p), headCap)
	return p
}

// peerReader is the bufio source: it applies the read deadline.
type peerReader peer

func (p *peerReader) Read(b []byte) (int, error) {
	if p.interrupt.Load() {
		return 0, errInterrupted
	}
	od := p.objectDeadline.Load()
	p.armDeadline(od)
	// A watcher stop or a bound set between the load and the deadline
	// would otherwise be overwritten by the longer idle deadline.
	if p.interrupt.Load() {
		return 0, errInterrupted
	}
	if od2 := p.objectDeadline.Load(); od2 != od {
		p.armDeadline(od2)
	}
	n, err := p.conn.Read(b)
	if n > 0 {
		p.active.Store(true)
		if w := p.firstByteWindow.Swap(0); w != 0 {
			p.objectDeadline.Store(time.Now().Add(time.Duration(w)).UnixNano())
		}
	}
	return n, err
}

// armDeadline sets the sooner of the idle deadline and object deadline od
// and records which one applies.
func (p *peerReader) armDeadline(od int64) {
	d := time.Now().Add(p.idle)
	object := false
	if od != 0 {
		if t := time.Unix(0, od); t.Before(d) {
			d, object = t, true
		}
	}
	p.objectArmed.Store(object)
	_ = p.conn.SetReadDeadline(d)
}

// Write sends b under the idle deadline.
func (p *peer) Write(b []byte) (int, error) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(p.idle))
	return p.conn.Write(b)
}

// setObjectDeadline bounds body receipt from now; a zero duration clears
// it along with any pending first-byte window.
func (p *peer) setObjectDeadline(d time.Duration) {
	if d == 0 {
		p.firstByteWindow.Store(0)
		p.objectDeadline.Store(0)
		return
	}
	p.objectDeadline.Store(time.Now().Add(d).UnixNano())
}

// boundFromFirstByte bounds the receipt of what the peer sends next to d
// from its first byte, so a dripped head cannot outlive the idle timeout.
func (p *peer) boundFromFirstByte(d time.Duration) {
	p.firstByteWindow.Store(int64(d))
}

// bound gives the peer window to finish what it is sending, including a
// read that is already blocked.
func (p *peer) bound(window time.Duration) {
	p.setObjectDeadline(window)
	_ = p.conn.SetReadDeadline(time.Now().Add(window))
}

// objectDeadlineHit reports whether the object deadline, not the idle
// one, bounded the read that just timed out.
func (p *peer) objectDeadlineHit() bool { return p.objectArmed.Load() }

func (p *peer) close() {
	p.closeOnce.Do(func() { p.conn.Close() })
}

// closeWrite half-closes the sending side when the transport supports it.
func (p *peer) closeWrite() {
	if cw, ok := p.conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// drain discards whatever the peer still sends until it stops or window
// passes, so a response written just before close is read rather than
// reset by unread bytes. Time is the only bound: a byte cap would reset
// every refused body longer than the cap.
func (p *peer) drain(window time.Duration) {
	_ = p.conn.SetReadDeadline(time.Now().Add(window))
	buf := make([]byte, copyBufSize)
	for {
		if _, err := p.conn.Read(buf); err != nil {
			return
		}
	}
}

// readHead reads one head through the blank line and returns exactly the
// bytes consumed, which the caller forwards unchanged or splices.
// errHeadTooLarge reports the cap; io.EOF with no bytes a clean close.
func readHead(r *bufio.Reader) ([]byte, error) {
	var raw []byte
	for {
		line, err := r.ReadSlice('\n')
		raw = append(raw, line...)
		if errors.Is(err, bufio.ErrBufferFull) || len(raw) > headCap {
			return raw, errHeadTooLarge
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(raw) > 0 {
				err = io.ErrUnexpectedEOF
			}
			return raw, err
		}
		if isBlankLine(line) && len(raw) > len(line) {
			return raw, nil
		}
	}
}

func isBlankLine(line []byte) bool {
	return len(line) == 1 || (len(line) == 2 && line[0] == '\r')
}

// closeWatch reports when a peer closes or fails while the gate is not
// reading from it. Stop before reading from the peer again; the returned
// channel is closed only when the peer went away before sending a byte.
type closeWatch struct {
	p      *peer
	closed chan struct{}
	done   chan struct{}
}

// guard wraps the watcher goroutine so that a panic in it is contained.
func watchClose(p *peer, guard func(func())) *closeWatch {
	w := &closeWatch{p: p, closed: make(chan struct{}), done: make(chan struct{})}
	go guard(func() {
		defer close(w.done)
		_, err := p.r.Peek(1)
		if err != nil && !isTimeout(err) {
			close(w.closed)
		}
	})
	return w
}

// stop ends the watch and reports whether the peer closed.
func (w *closeWatch) stop() bool {
	w.p.interrupt.Store(true)
	_ = w.p.conn.SetReadDeadline(time.Now())
	<-w.done
	_ = w.p.conn.SetReadDeadline(time.Time{})
	w.p.interrupt.Store(false)
	select {
	case <-w.closed:
		return true
	default:
		return false
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
