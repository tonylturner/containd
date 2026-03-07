// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ICAPClient is a minimal ICAP client to probe servers and perform simple scans.
// This is intentionally lightweight; richer REQMOD/RESPMOD handling will be added alongside
// real file extraction and verdict handling.
type ICAPClient struct {
	Timeout time.Duration
	MaxSize int64
}

func NewICAPClient() *ICAPClient {
	return &ICAPClient{Timeout: 5 * time.Second, MaxSize: 0}
}

// Probe ensures the ICAP server is reachable (TCP connect + OPTIONS).
func (c *ICAPClient) Probe(ctx context.Context, srv config.ICAPServer) error {
	if c == nil {
		return fmt.Errorf("icap client nil")
	}
	addr := strings.TrimSpace(srv.Address)
	if addr == "" {
		return fmt.Errorf("icap address empty")
	}
	network := "tcp"
	dialer := net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return err
	}
	service := srv.Service
	if strings.TrimSpace(service) == "" {
		service = "avscan"
	}
	req := fmt.Sprintf("OPTIONS icap://%s/%s ICAP/1.0\r\nHost: %s\r\n\r\n", addr, service, addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "ICAP/1.0 2") {
		return fmt.Errorf("icap probe unexpected response: %s", strings.TrimSpace(line))
	}
	return nil
}

// Scan performs a minimal RESPmod-like request and treats 2xx as clean, 4xx/5xx as errors, and X-Verdict headers as detections.
func (c *ICAPClient) Scan(ctx context.Context, srv config.ICAPServer, payload []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("icap client nil")
	}
	if c.MaxSize > 0 && int64(len(payload)) > c.MaxSize {
		return "skipped", fmt.Errorf("payload exceeds max size")
	}
	addr := strings.TrimSpace(srv.Address)
	if addr == "" {
		return "", fmt.Errorf("icap address empty")
	}
	network := "tcp"
	dialer := net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return "", err
	}
	service := srv.Service
	if strings.TrimSpace(service) == "" {
		service = "avscan"
	}
	// Minimal RESPmod-like request with dummy HTTP response encapsulated.
	encapsulated := fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n", len(payload)+len("HTTP/1.1 200 OK\r\n\r\n"))
	req := fmt.Sprintf("RESPMOD icap://%s/%s ICAP/1.0\r\nHost: %s\r\nAllow: 204\r\n%s\r\nHTTP/1.1 200 OK\r\n\r\n", addr, service, addr, encapsulated)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}
	if _, err := conn.Write(payload); err != nil {
		return "", err
	}
	r := bufio.NewReader(conn)
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(statusLine, "ICAP/1.0 2") {
		return "error", fmt.Errorf("icap scan failed: %s", strings.TrimSpace(statusLine))
	}
	verdict := "clean"
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		l := strings.TrimSpace(line)
		if l == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(l), "x-icap-status:") && strings.Contains(strings.ToLower(l), "virusfound") {
			verdict = "malware"
		}
	}
	return verdict, nil
}
