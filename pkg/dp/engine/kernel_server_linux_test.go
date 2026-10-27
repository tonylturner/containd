// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// answerFunc handles the next message of a connection from src at the
// start of buf: it returns the bytes it consumed, 0 while the message is
// incomplete, and the reply to write. An error ends the connection.
type answerFunc func(src string, buf []byte) (consumed int, reply []byte, err error)

// kernelServer is a TCP server in the lab's server namespace. It records,
// per client address, every byte received, before it answers a message,
// and how each connection ended.
type kernelServer struct {
	answer answerFunc
	mu     sync.Mutex
	ln     net.Listener
	conns  []net.Conn
	bytes  map[string]int
	ends   map[string][]error
}

func startKernelServer(t *testing.T, port int, answer answerFunc) *kernelServer {
	t.Helper()
	s := &kernelServer{answer: answer, bytes: map[string]int{}, ends: map[string][]error{}}
	err := inNetns(fcServerNS, func() (err error) {
		s.ln, err = net.Listen("tcp", net.JoinHostPort(fcServerIP, strconv.Itoa(port)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := s.ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			go s.serve(c)
		}
	}()
	t.Cleanup(func() {
		_ = s.ln.Close()
		<-done
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range s.conns {
			_ = c.Close()
		}
	})
	return s
}

func (s *kernelServer) serve(c net.Conn) {
	src := c.RemoteAddr().(*net.TCPAddr).IP.String()
	err := s.exchange(c, src)
	s.mu.Lock()
	s.ends[src] = append(s.ends[src], err)
	s.mu.Unlock()
}

// exchange answers the messages of one connection and returns the error
// that ended it.
func (s *kernelServer) exchange(c net.Conn, src string) error {
	var buf []byte
	tmp := make([]byte, 1024)
	for {
		n, err := c.Read(tmp)
		s.mu.Lock()
		s.bytes[src] += n
		s.mu.Unlock()
		buf = append(buf, tmp[:n]...)
		for {
			consumed, reply, aerr := s.answer(src, buf)
			if aerr != nil {
				return aerr
			}
			if consumed == 0 {
				break
			}
			buf = buf[consumed:]
			if len(reply) == 0 {
				continue
			}
			if _, werr := c.Write(reply); werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

// received returns the bytes received from src.
func (s *kernelServer) received(src string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes[src]
}

// ended waits up to fcReplyWait for n connections from src to end and
// returns how they ended.
func (s *kernelServer) ended(t *testing.T, src string, n int) []error {
	t.Helper()
	deadline := time.Now().Add(fcReplyWait)
	for {
		s.mu.Lock()
		ends := slices.Clone(s.ends[src])
		s.mu.Unlock()
		if len(ends) >= n {
			return ends
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections from %s ended, want %d", len(ends), src, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
