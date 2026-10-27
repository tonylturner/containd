// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

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

// startLinuxShell runs a Linux shell as the session's program and sends its
// exit status once the shell has exited and its input and output copies have
// stopped. It services the session's remaining requests, such as
// window-change, until the channel closes.
func (s *Server) startLinuxShell(ctx context.Context, username string, ch ssh.Channel, requests <-chan *ssh.Request, pr *ptyRequest) {
	cmd, release := s.shellCommand(ctx, username, pr, ch)
	defer release()

	ptmx, err := startPTY(cmd, pr)
	if err != nil {
		s.logger.Errorf("failed to start linux shell: %v", err)
		writeTTY(ch, "failed to start shell\n")
		sendExitStatus(ch, exitFailure)
		return
	}
	go serveShellRequests(requests, ptmx)

	input := newSessionInput(ch)
	defer input.close()
	exited := make(chan struct{})
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		input.forward(ptmx, exited)
	}()
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		_, _ = io.Copy(ch, ptmx)
	}()

	waitErr := cmd.Wait()
	close(exited)
	closeShellPTY(ptmx, outputDone)
	<-inputDone
	s.sendShellExit(ch, waitErr)
}

// serveShellRequests answers a shell session's requests until its channel
// closes, applying window-change to the PTY.
func serveShellRequests(requests <-chan *ssh.Request, ptmx *os.File) {
	for req := range requests {
		switch req.Type {
		case "window-change":
			if w, h, ok := parseWindowChange(req.Payload); ok {
				setPTYSize(ptmx, w, h)
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
}

// startPTY starts cmd on a PTY whose reads Close interrupts. A process the
// shell leaves running can hold the terminal open after the shell exits, and
// a blocking read would then outlive the session.
func startPTY(cmd *exec.Cmd, pr *ptyRequest) (*os.File, error) {
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(pr.Height), Cols: uint16(pr.Width)})
	if err != nil {
		return nil, err
	}
	// A PTY the runtime poller cannot watch (macOS) keeps blocking reads:
	// non-blocking reads would fail there instead of waiting.
	if errors.Is(ptmx.SetReadDeadline(time.Time{}), os.ErrNoDeadline) {
		return ptmx, nil
	}
	// (*os.File).Fd leaves the descriptor blocking; reads wait in the
	// poller again once it is non-blocking.
	if err := syscall.SetNonblock(int(ptmx.Fd()), true); err != nil {
		_ = ptmx.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	return ptmx, nil
}

// setPTYSize resizes the terminal. It avoids pty.Setsize, whose use of
// (*os.File).Fd would make the PTY blocking again.
func setPTYSize(ptmx *os.File, width, height uint32) {
	conn, err := ptmx.SyscallConn()
	if err != nil {
		return
	}
	_ = conn.Control(func(fd uintptr) {
		_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(height), Col: uint16(width)})
	})
}

// shellOutputGrace bounds the wait for output a shell wrote before it
// exited. A process the shell left running can keep the terminal open, so
// the output copy may not end on its own.
const shellOutputGrace = time.Second

// closeShellPTY closes the PTY of a shell that has exited and returns once
// the output copy has stopped. Output already written is delivered first,
// waiting at most shellOutputGrace.
func closeShellPTY(ptmx *os.File, outputDone <-chan struct{}) {
	select {
	case <-outputDone:
	case <-time.After(shellOutputGrace):
	}
	_ = ptmx.Close()
	<-outputDone
}

// startLinuxShellInline runs a Linux shell from the appliance CLI and returns
// when it exits. The shell first receives what the CLI has buffered but not
// read; input it has not taken when it exits stays for the CLI.
func (s *Server) startLinuxShellInline(ctx context.Context, username string, term *sessionIO, buffered *bufio.Reader, pr *ptyRequest, windowCh <-chan ptyRequest) {
	cmd, release := s.shellCommand(ctx, username, pr, term)
	defer release()

	ptmx, err := startPTY(cmd, pr)
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
	wg.Add(2)
	go func() {
		defer wg.Done()
		term.forward(ptmx, exited)
	}()
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
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
				setPTYSize(ptmx, wc.Width, wc.Height)
			}
		}
	}()

	_ = cmd.Wait()
	close(exited)
	closeShellPTY(ptmx, outputDone)
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
