// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// ptyRequest holds parsed data from an SSH "pty-req" request.
type ptyRequest struct {
	Term   string
	Width  uint32
	Height uint32
}

// parsePtyReq extracts terminal info from the SSH pty-req payload.
func parsePtyReq(data []byte) (ptyRequest, bool) {
	// Wire format: string(term), uint32(width), uint32(height), uint32(pxW), uint32(pxH), string(modes).
	if len(data) < 4 {
		return ptyRequest{}, false
	}
	termLen := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if uint32(len(data)) < termLen {
		return ptyRequest{}, false
	}
	term := string(data[:termLen])
	data = data[termLen:]
	if len(data) < 16 { // 4 uint32 fields
		return ptyRequest{}, false
	}
	width := binary.BigEndian.Uint32(data[0:4])
	height := binary.BigEndian.Uint32(data[4:8])
	return ptyRequest{Term: term, Width: width, Height: height}, true
}

// parseWindowChange extracts dimensions from an SSH "window-change" payload.
func parseWindowChange(data []byte) (uint32, uint32, bool) {
	if len(data) < 8 {
		return 0, 0, false
	}
	w := binary.BigEndian.Uint32(data[0:4])
	h := binary.BigEndian.Uint32(data[4:8])
	return w, h, true
}

// startLinuxShell launches /bin/bash with a real PTY and wires it to the SSH channel.
// It consumes the remaining SSH request channel to handle window-change events.
func (s *Server) startLinuxShell(ctx context.Context, username string, ch ssh.Channel, requests <-chan *ssh.Request, pr *ptyRequest) {
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}

	cmd := exec.CommandContext(ctx, shell, "--login")
	cmd.Env = buildShellEnv(username, pr)
	// Use a new session so we can signal the process group on cleanup.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	winSize := &pty.Winsize{Rows: uint16(pr.Height), Cols: uint16(pr.Width)}
	ptmx, err := pty.StartWithSize(cmd, winSize)
	if err != nil {
		s.logger.Errorf("failed to start linux shell: %v", err)
		return
	}

	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			ptmx.Close()
		})
	}
	defer cleanup()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Copy SSH channel -> PTY (stdin).
	go func() {
		defer cancel()
		io.Copy(ptmx, ch)
	}()

	// Copy PTY -> SSH channel (stdout).
	go func() {
		defer cancel()
		io.Copy(ch, ptmx)
	}()

	// Handle SSH requests (window-change).
	go func() {
		for req := range requests {
			switch req.Type {
			case "window-change":
				w, h, ok := parseWindowChange(req.Payload)
				if ok {
					pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	// Wait for bash to exit.
	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	// Send exit-status to the SSH client.
	exitPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(exitPayload, uint32(exitCode))
	ch.SendRequest("exit-status", false, exitPayload)
}

// startLinuxShellInline launches a bash shell from within the appliance REPL.
// It blocks until bash exits, then returns control to the caller (REPL resumes).
func (s *Server) startLinuxShellInline(ctx context.Context, username string, ch ssh.Channel, pr *ptyRequest, windowCh <-chan ptyRequest) {
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}

	cmd := exec.CommandContext(ctx, shell, "--login")
	cmd.Env = buildShellEnv(username, pr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	winSize := &pty.Winsize{Rows: uint16(pr.Height), Cols: uint16(pr.Width)}
	ptmx, err := pty.StartWithSize(cmd, winSize)
	if err != nil {
		s.logger.Errorf("failed to start inline linux shell: %v", err)
		return
	}

	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			ptmx.Close()
		})
	}
	defer cleanup()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Copy SSH channel -> PTY (stdin).
	go func() {
		defer cancel()
		io.Copy(ptmx, ch)
	}()

	// Copy PTY -> SSH channel (stdout).
	go func() {
		defer cancel()
		io.Copy(ch, ptmx)
	}()

	// Handle window-change events forwarded from the session handler.
	if windowCh != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case wc, ok := <-windowCh:
					if !ok {
						return
					}
					pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(wc.Height), Cols: uint16(wc.Width)})
				}
			}
		}()
	}

	cmd.Wait()
}

func buildShellEnv(username string, pr *ptyRequest) []string {
	term := "xterm-256color"
	if pr != nil && pr.Term != "" {
		term = pr.Term
	}
	return []string{
		"TERM=" + term,
		"USER=" + username,
		"HOME=/root",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}
}
