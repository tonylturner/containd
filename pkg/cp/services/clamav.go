// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var errClamdOversized = errors.New("clamd scan limit exceeded")

const (
	// clamdMaxReply bounds a single clamd reply. Verdicts, versions and
	// errors are one short line; anything longer is a protocol violation.
	clamdMaxReply = 4096
	// clamdChunkSize is the INSTREAM chunk size. clamd limits each chunk to
	// StreamMaxLength, which defaults to far more than this.
	clamdChunkSize = 64 << 10
)

// ClamAVClient speaks the clamd Unix-socket protocol in NUL-delimited mode:
// every command is sent as "z<COMMAND>\0" and every reply ends with "\0".
type ClamAVClient struct {
	// Timeout bounds connecting to clamd. The exchange itself is bounded by
	// the ctx deadline when there is one, otherwise by Timeout as well.
	Timeout time.Duration
	Socket  string
}

// ClamdVerdict is one parsed INSTREAM reply.
type ClamdVerdict struct {
	Verdict   string // clean or malware
	Signature string // detection name when Verdict is malware
}

func (c *ClamAVClient) dial(ctx context.Context) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("clamav client nil")
	}
	if strings.TrimSpace(c.Socket) == "" {
		return nil, errors.New("clamav socket not set")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultAVTimeout
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		deadline = time.Now().Add(timeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// command sends a single argument-free command and returns its reply.
func (c *ClamAVClient) command(ctx context.Context, name string) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := writeClamd(conn, []byte("z"+name+"\x00")); err != nil {
		return "", err
	}
	return readClamdReply(conn)
}

// Ping reports whether clamd is accepting commands with a loaded database.
func (c *ClamAVClient) Ping(ctx context.Context) error {
	reply, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if reply != "PONG" {
		return fmt.Errorf("clamd ping: unexpected reply %q", reply)
	}
	return nil
}

// Version returns clamd's "ClamAV <engine>/<db version>/<db date>" string.
func (c *ClamAVClient) Version(ctx context.Context) (string, error) {
	reply, err := c.command(ctx, "VERSION")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(reply, "ClamAV ") {
		return "", fmt.Errorf("clamd version: unexpected reply %q", reply)
	}
	return reply, nil
}

// Reload asks clamd to reload its signature databases.
func (c *ClamAVClient) Reload(ctx context.Context) error {
	reply, err := c.command(ctx, "RELOAD")
	if err != nil {
		return err
	}
	if reply != "RELOADING" {
		return fmt.Errorf("clamd reload: unexpected reply %q", reply)
	}
	return nil
}

// Scan streams payload with INSTREAM and parses the verdict. A clamd ERROR
// reply, a truncated reply or an unrecognised reply is an error, never clean.
func (c *ClamAVClient) Scan(ctx context.Context, payload io.Reader, size int64) (ClamdVerdict, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return ClamdVerdict{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := writeClamd(conn, []byte("zINSTREAM\x00")); err != nil {
		return ClamdVerdict{}, err
	}
	if err := writeInstream(conn, payload, size); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrShortWrite) {
			return ClamdVerdict{}, err
		}
		// clamd answers a limit violation and closes; surface its reason.
		if reply, rerr := readClamdReply(conn); rerr == nil {
			if _, perr := parseClamdScanReply(reply); errors.Is(perr, errClamdOversized) {
				return ClamdVerdict{}, perr
			}
		}
		return ClamdVerdict{}, err
	}
	reply, err := readClamdReply(conn)
	if err != nil {
		return ClamdVerdict{}, err
	}
	return parseClamdScanReply(reply)
}

// writeClamd rejects short writes even when a writer returns no error.
func writeClamd(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func writeInstream(w io.Writer, payload io.Reader, size int64) error {
	if size < 0 {
		return errors.New("negative stream size")
	}
	var hdr [4]byte
	buf := make([]byte, clamdChunkSize)
	for size > 0 {
		n := min(size, int64(len(buf)))
		if _, err := io.ReadFull(payload, buf[:n]); err != nil {
			return err
		}
		binary.BigEndian.PutUint32(hdr[:], uint32(n)) // #nosec G115 -- n <= clamdChunkSize
		if err := writeClamd(w, hdr[:]); err != nil {
			return err
		}
		if err := writeClamd(w, buf[:n]); err != nil {
			return err
		}
		size -= n
	}
	binary.BigEndian.PutUint32(hdr[:], 0)
	return writeClamd(w, hdr[:])
}

// readClamdReply reads one NUL-terminated reply of at most clamdMaxReply bytes.
func readClamdReply(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, clamdMaxReply+1))
	line, err := br.ReadBytes(0)
	if len(line) > clamdMaxReply {
		return "", errors.New("clamd reply exceeds size limit")
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", errors.New("clamd reply truncated")
		}
		return "", err
	}
	return string(bytes.TrimSpace(line[:len(line)-1])), nil
}

func parseClamdScanReply(reply string) (ClamdVerdict, error) {
	// INSTREAM replies name the scanned object "stream".
	body, ok := strings.CutPrefix(reply, "stream: ")
	switch {
	case strings.Contains(reply, "Heuristics.Limits.Exceeded") || strings.Contains(strings.ToLower(reply), "size limit exceeded"):
		return ClamdVerdict{}, fmt.Errorf("%w: %s", errClamdOversized, reply)
	case strings.HasSuffix(reply, " ERROR"):
		return ClamdVerdict{}, fmt.Errorf("clamd: %s", reply)
	case ok && body == "OK":
		return ClamdVerdict{Verdict: "clean"}, nil
	case ok && strings.HasSuffix(body, " FOUND"):
		sig := strings.TrimSpace(strings.TrimSuffix(body, " FOUND"))
		if sig == "" {
			return ClamdVerdict{}, fmt.Errorf("clamd: detection without signature: %q", reply)
		}
		return ClamdVerdict{Verdict: "malware", Signature: sig}, nil
	}
	return ClamdVerdict{}, fmt.Errorf("clamd: unexpected reply %q", reply)
}
