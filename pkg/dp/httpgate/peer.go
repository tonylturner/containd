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
	// pipelineCap bounds the bytes a close watcher keeps for the next read
	// while the gate is not reading: requests pipelined during a hold.
	// Beyond it the peer counts as gone, so liveness is never traded for
	// buffering.
	pipelineCap = headCap
)

var errHeadTooLarge = errors.New("httpgate: head exceeds 64 KiB")

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
	// writeBound is the unix-nanosecond deadline of writes to the peer
	// while another goroutine bounds them; 0 when none.
	writeBound atomic.Int64
	// interrupt tells a close watcher that its read was cut short by stop
	// rather than by the peer.
	interrupt atomic.Bool
	// pending holds bytes a close watcher read from the socket; the next
	// Read drains it before touching the socket again.
	pending []byte
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
	if len(p.pending) > 0 {
		n := copy(b, p.pending)
		p.pending = p.pending[n:]
		if len(p.pending) == 0 {
			p.pending = nil
		}
		p.noteBytes()
		return n, nil
	}
	od := p.objectDeadline.Load()
	p.armDeadline(od)
	// A bound set from another goroutine between the load and the
	// deadline would otherwise be overwritten by the longer idle deadline.
	if od2 := p.objectDeadline.Load(); od2 != od {
		p.armDeadline(od2)
	}
	n, err := p.conn.Read(b)
	if n > 0 {
		p.noteBytes()
	}
	return n, err
}

// noteBytes records that the peer delivered bytes: it is active, and a
// pending first-byte window becomes the object deadline.
func (p *peerReader) noteBytes() {
	p.active.Store(true)
	if w := p.firstByteWindow.Swap(0); w != 0 {
		p.objectDeadline.Store(time.Now().Add(time.Duration(w)).UnixNano())
	}
}

// armDeadline sets the sooner of the idle deadline and object deadline od
// and records which one applies.
func (p *peerReader) armDeadline(od int64) {
	d, object := (*peer)(p).soonerDeadline(od)
	p.objectArmed.Store(object)
	_ = p.conn.SetReadDeadline(d)
}

// soonerDeadline returns the idle deadline from now, or bound (a unix
// nanosecond time, 0 for none) when that comes first, and whether bound
// applies.
func (p *peer) soonerDeadline(bound int64) (time.Time, bool) {
	d := time.Now().Add(p.idle)
	if bound != 0 {
		if t := time.Unix(0, bound); t.Before(d) {
			return t, true
		}
	}
	return d, false
}

// Write sends b under the idle deadline, or the write bound when sooner.
func (p *peer) Write(b []byte) (int, error) {
	wb := p.writeBound.Load()
	p.armWriteDeadline(wb)
	// A bound set from another goroutine between the load and the
	// deadline would otherwise be overwritten by the longer idle deadline.
	if wb2 := p.writeBound.Load(); wb2 != wb {
		p.armWriteDeadline(wb2)
	}
	return p.conn.Write(b)
}

func (p *peer) armWriteDeadline(wb int64) {
	d, _ := p.soonerDeadline(wb)
	_ = p.conn.SetWriteDeadline(d)
}

// boundWrite gives the peer window to accept what is being written to it,
// including a write that is already blocked; a zero window clears the
// bound. Writes that start later re-arm the idle deadline themselves.
func (p *peer) boundWrite(window time.Duration) {
	if window == 0 {
		p.writeBound.Store(0)
		return
	}
	d := time.Now().Add(window)
	p.writeBound.Store(d.UnixNano())
	_ = p.conn.SetWriteDeadline(d)
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

// reset closes the connection with a TCP reset instead of a FIN, so a
// recipient holding a prefix of an object learns that it is incomplete
// and unread bytes are discarded rather than drained. A transport
// without SO_LINGER is closed plainly.
func (p *peer) reset() {
	p.closeOnce.Do(func() {
		if l, ok := p.conn.(interface{ SetLinger(int) error }); ok {
			_ = l.SetLinger(0)
		}
		p.conn.Close()
	})
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

// closeWatch observes a peer while the gate is not reading from it and
// reports when it closes or fails. closed is closed when the peer went
// away or sent more than pipelineCap bytes meanwhile; overflow tells the
// two apart once done is closed. Stop before reading from the peer again.
type closeWatch struct {
	p        *peer
	closed   chan struct{}
	done     chan struct{}
	overflow bool
}

// watchClose reads the socket itself rather than peeking through the
// buffered reader, so bytes already buffered (a pipelined request) cannot
// satisfy the watch and hide a later close. What the peer sends is kept
// for the next read. guard contains a panic in the watcher goroutine.
func watchClose(p *peer, guard func(func())) *closeWatch {
	w := &closeWatch{p: p, closed: make(chan struct{}), done: make(chan struct{})}
	p.interrupt.Store(false)
	_ = p.conn.SetReadDeadline(time.Time{})
	go guard(func() {
		defer close(w.done)
		buf := make([]byte, 4096)
		for {
			n, err := p.conn.Read(buf)
			if n > 0 {
				if len(p.pending)+n > pipelineCap {
					w.overflow = true
					close(w.closed)
					return
				}
				p.pending = append(p.pending, buf[:n]...)
			}
			if err != nil {
				// Only stop sets a deadline while watching, so a timeout
				// is the stop itself.
				if !isTimeout(err) || !p.interrupt.Load() {
					close(w.closed)
				}
				return
			}
		}
	})
	return w
}

// stop ends the watch and reports whether the peer went away.
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
