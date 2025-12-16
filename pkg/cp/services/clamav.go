package services

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ClamAVClient speaks the clamd TCP/UNIX protocol (INSTREAM).
type ClamAVClient struct {
	Timeout time.Duration
	Socket  string
}

func (c *ClamAVClient) Scan(ctx context.Context, payload []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("clamav client nil")
	}
	if strings.TrimSpace(c.Socket) == "" {
		return "", fmt.Errorf("clamav socket not set")
	}
	dialer := net.Dialer{Timeout: c.Timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := conn.Write([]byte("zINSTREAM\000")); err != nil {
		return "", err
	}
	// INSTREAM chunk: 32-bit length prefix.
	chunk := make([]byte, 4+len(payload))
	chunk[0] = byte(len(payload) >> 24)
	chunk[1] = byte(len(payload) >> 16)
	chunk[2] = byte(len(payload) >> 8)
	chunk[3] = byte(len(payload))
	copy(chunk[4:], payload)
	if _, err := conn.Write(chunk); err != nil {
		return "", err
	}
	// Terminate stream.
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", err
	}
	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	resp = strings.TrimSpace(resp)
	if strings.Contains(resp, "FOUND") {
		return "malware", nil
	}
	if strings.Contains(resp, "ERROR") {
		return "error", fmt.Errorf("%s", resp)
	}
	return "clean", nil
}
