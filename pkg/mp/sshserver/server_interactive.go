// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/audit"
)

type interactiveSession struct {
	server   *Server
	ctx      context.Context
	username string
	rw       io.ReadWriter
	reader   *bufio.Reader
	reg      *cli.Registry
}

func newInteractiveSession(s *Server, ctx context.Context, username string, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) *interactiveSession {
	return &interactiveSession{
		server:   s,
		ctx:      ctx,
		username: username,
		rw:       rw,
		reader:   reader,
		reg:      reg,
	}
}

func (s *interactiveSession) writeLn(msg string) {
	writeTTY(s.rw, msg+"\n")
}

func (s *interactiveSession) exec(line string) bool {
	var out strings.Builder
	err := s.reg.ParseAndExecute(s.ctx, line, &out)
	if out.Len() > 0 {
		writeTTY(s.rw, out.String())
		if !strings.HasSuffix(out.String(), "\n") && !strings.HasSuffix(out.String(), "\r\n") {
			s.writeLn("")
		}
	}
	if err != nil {
		s.writeLn("error: " + err.Error())
		return false
	}
	return true
}

func (s *interactiveSession) execWithOutput(line string) (strings.Builder, error) {
	var out strings.Builder
	err := s.reg.ParseAndExecute(s.ctx, line, &out)
	if out.Len() > 0 {
		writeTTY(s.rw, out.String())
		if !strings.HasSuffix(out.String(), "\n") && !strings.HasSuffix(out.String(), "\r\n") {
			s.writeLn("")
		}
	}
	return out, err
}

func (s *interactiveSession) ask(prompt string) (string, bool) {
	_, _ = io.WriteString(s.rw, "\r"+prompt)
	line, ok := readLineInteractive(s.reader, s.rw)
	if !ok {
		return "", false
	}
	line = strings.TrimSpace(line)
	if line == "\x03" {
		s.writeLn("^C")
		return "", false
	}
	return line, true
}

// askSecret reads a line like ask but never echoes the typed characters. The
// value is returned as typed; only the line ending is consumed.
func (s *interactiveSession) askSecret(prompt string) (string, bool) {
	_, _ = io.WriteString(s.rw, "\r"+prompt)
	line, ok := readSecretInteractive(s.reader, s.rw)
	if !ok {
		return "", false
	}
	if line == "\x03" {
		s.writeLn("^C")
		return "", false
	}
	return line, true
}

// askNewPassword reads a new password and its confirmation without echo. A
// blank first entry returns "" with ok true so the caller can skip the step.
// Cancelling or a confirmation mismatch returns ok false.
func (s *interactiveSession) askNewPassword(prompt string) (string, bool) {
	pw, ok := s.askSecret(prompt)
	if !ok {
		return "", false
	}
	if strings.TrimSpace(pw) == "" {
		return "", true
	}
	confirm, ok := s.askSecret("Confirm new password: ")
	if !ok {
		return "", false
	}
	if confirm != pw {
		s.writeLn("error: passwords do not match")
		return "", false
	}
	return pw, true
}

func (s *interactiveSession) writeAudit(action, target string) {
	if s.server.opts.AuditStore == nil {
		return
	}
	_ = s.server.opts.AuditStore.Add(s.ctx, audit.Record{
		Actor:  s.username,
		Source: "ssh",
		Action: action,
		Target: target,
		Result: "success",
	})
}

// readLineInteractive reads one line from a terminal session, echoing each
// accepted character and handling backspace.
func readLineInteractive(r *bufio.Reader, out io.Writer) (string, bool) {
	return readTerminalLine(r, out, true)
}

// readSecretInteractive reads one line like readLineInteractive without
// echoing characters or backspace erasures. Only the final newline is written.
func readSecretInteractive(r *bufio.Reader, out io.Writer) (string, bool) {
	return readTerminalLine(r, out, false)
}

// readTerminalLine returns "\x03" for Ctrl-C and false for Ctrl-D on an empty
// line or a read error. Other control characters are dropped.
func readTerminalLine(r *bufio.Reader, out io.Writer, echo bool) (string, bool) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", false
		}
		if b == 0x04 && len(buf) == 0 {
			return "", false
		}
		if b == 0x03 {
			return "\x03", true
		}
		if b == '\n' || b == '\r' {
			writeTTY(out, "\n")
			break
		}
		if b == 0x08 || b == 0x7f {
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if echo {
					writeRaw(out, "\b \b")
				}
			}
			continue
		}
		if b < 0x20 {
			continue
		}
		buf = append(buf, b)
		if echo {
			writeRaw(out, string([]byte{b}))
		}
	}
	return string(buf), true
}
