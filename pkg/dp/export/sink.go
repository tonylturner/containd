// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package export

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
)

// Sink is a destination for exported event data.
type Sink interface {
	Write(data []byte) error
	Close() error
}

// FileSink writes to a log file. It creates or appends to the file.
type FileSink struct {
	mu   sync.Mutex
	path string
	file *os.File
}

// NewFileSink opens or creates the file at path for appending.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open file sink %q: %w", path, err)
	}
	return &FileSink{path: path, file: f}, nil
}

func (s *FileSink) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return fmt.Errorf("file sink closed")
	}
	_, err := s.file.Write(data)
	if err != nil {
		return fmt.Errorf("file sink write: %w", err)
	}
	// Ensure newline separation.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		_, _ = s.file.Write([]byte{'\n'})
	}
	return nil
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		return err
	}
	return nil
}

// UDPSink sends data to a remote syslog server over UDP.
type UDPSink struct {
	addr string
	conn net.Conn
}

// NewUDPSink dials the target address over UDP.
func NewUDPSink(addr string) (*UDPSink, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp %q: %w", addr, err)
	}
	return &UDPSink{addr: addr, conn: conn}, nil
}

func (s *UDPSink) Write(data []byte) error {
	_, err := s.conn.Write(data)
	return err
}

func (s *UDPSink) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// TCPSink sends data to a remote syslog server over TCP.
type TCPSink struct {
	addr string
	conn net.Conn
}

// NewTCPSink dials the target address over TCP.
func NewTCPSink(addr string) (*TCPSink, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp %q: %w", addr, err)
	}
	return &TCPSink{addr: addr, conn: conn}, nil
}

func (s *TCPSink) Write(data []byte) error {
	_, err := s.conn.Write(data)
	return err
}

func (s *TCPSink) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// NewSink parses a target URL and creates the appropriate Sink.
//
// Supported schemes:
//   - "file:///path/to/export.log" -> FileSink
//   - "udp://host:514"            -> UDPSink
//   - "tcp://host:514"            -> TCPSink
func NewSink(target string) (Sink, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse sink target %q: %w", target, err)
	}
	switch u.Scheme {
	case "file":
		path := u.Path
		if path == "" {
			return nil, fmt.Errorf("file sink requires a path: %q", target)
		}
		return NewFileSink(path)
	case "udp":
		host := u.Host
		if host == "" {
			return nil, fmt.Errorf("udp sink requires host:port: %q", target)
		}
		return NewUDPSink(host)
	case "tcp":
		host := u.Host
		if host == "" {
			return nil, fmt.Errorf("tcp sink requires host:port: %q", target)
		}
		return NewTCPSink(host)
	default:
		return nil, fmt.Errorf("unsupported sink scheme %q in %q", u.Scheme, target)
	}
}
