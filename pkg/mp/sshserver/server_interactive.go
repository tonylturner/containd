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
