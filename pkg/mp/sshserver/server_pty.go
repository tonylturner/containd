// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cli"
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
	cmd, release := s.shellCommand(ctx, username, pr, ch)
	defer release()

	winSize := &pty.Winsize{Rows: uint16(pr.Height), Cols: uint16(pr.Width)}
	ptmx, err := pty.StartWithSize(cmd, winSize)
	if err != nil {
		s.logger.Errorf("failed to start linux shell: %v", err)
		writeTTY(ch, "failed to start shell\n")
		sendExitStatus(ch, exitFailure)
		return
	}

	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			ptmx.Close()
		})
	}
	defer cleanup()

	_, cancel := context.WithCancel(ctx)
	defer cancel()

	// Copy SSH channel -> PTY (stdin).
	go func() {
		defer cancel()
		_, _ = io.Copy(ptmx, ch)
	}()

	// Copy PTY -> SSH channel (stdout).
	go func() {
		defer cancel()
		_, _ = io.Copy(ch, ptmx)
	}()

	// Handle SSH requests (window-change).
	go func() {
		for req := range requests {
			switch req.Type {
			case "window-change":
				w, h, ok := parseWindowChange(req.Payload)
				if ok {
					_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)})
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	// Wait for bash to exit.
	s.sendShellExit(ch, cmd.Wait())
}

// startLinuxShellInline runs a Linux shell from the appliance CLI and returns
// when it exits. The shell first receives what the CLI has buffered but not
// read; input it has not taken when it exits stays for the CLI.
func (s *Server) startLinuxShellInline(ctx context.Context, username string, term *sessionIO, buffered *bufio.Reader, pr *ptyRequest, windowCh <-chan ptyRequest) {
	cmd, release := s.shellCommand(ctx, username, pr, term)
	defer release()

	winSize := &pty.Winsize{Rows: uint16(pr.Height), Cols: uint16(pr.Width)}
	ptmx, err := pty.StartWithSize(cmd, winSize)
	if err != nil {
		s.logger.Errorf("failed to start inline linux shell: %v", err)
		writeTTY(term, "failed to start shell\n")
		return
	}
	if n := buffered.Buffered(); n > 0 {
		ahead, _ := buffered.Peek(n)
		_, _ = ptmx.Write(ahead)
		_, _ = buffered.Discard(n)
	}

	exited := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		term.forward(ptmx, exited)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(term.Writer, ptmx)
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-exited:
				return
			case wc, ok := <-windowCh:
				if !ok {
					return
				}
				_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(wc.Height), Cols: uint16(wc.Width)})
			}
		}
	}()

	_ = cmd.Wait()
	close(exited)
	_ = ptmx.Close()
	wg.Wait()
}

// shellCommand prepares a Linux login shell for an SSH login. CLI processes
// in it reach management as that login through its shell API, which
// release closes. The shell starts in a new session so its process group
// can be signalled.
func (s *Server) shellCommand(ctx context.Context, username string, pr *ptyRequest, out io.Writer) (*exec.Cmd, func()) {
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.CommandContext(ctx, shell, "--login")
	cmd.Env = buildShellEnv(username, pr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	release := func() {}
	if conn := connectionFromContext(ctx); conn != nil {
		api, err := s.openShellAPI(conn)
		if err != nil {
			s.logger.Errorf("ssh shell API: %v", err)
			writeTTY(out, "warning: containd cli cannot use this SSH login in this shell: "+err.Error()+"\n")
		} else {
			cmd.Env = append(cmd.Env, cli.EnvSSHAPISocket+"="+api.socket)
			release = api.close
		}
	}
	return cmd, release
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
