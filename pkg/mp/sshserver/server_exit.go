// SPDX-License-Identifier: Apache-2.0

package sshserver

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// Exit statuses of a session's command (RFC 4254 section 6.10).
const (
	exitSuccess uint32 = 0
	exitFailure uint32 = 1
)

// sendExitStatus reports the exit status of the session's command or shell
// before the channel closes, so clients do not report a missing status.
func sendExitStatus(ch ssh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

// exitSignalNames are the signal names RFC 4254 section 6.10 defines.
var exitSignalNames = map[syscall.Signal]ssh.Signal{
	syscall.SIGABRT: ssh.SIGABRT,
	syscall.SIGALRM: ssh.SIGALRM,
	syscall.SIGFPE:  ssh.SIGFPE,
	syscall.SIGHUP:  ssh.SIGHUP,
	syscall.SIGILL:  ssh.SIGILL,
	syscall.SIGINT:  ssh.SIGINT,
	syscall.SIGKILL: ssh.SIGKILL,
	syscall.SIGPIPE: ssh.SIGPIPE,
	syscall.SIGQUIT: ssh.SIGQUIT,
	syscall.SIGSEGV: ssh.SIGSEGV,
	syscall.SIGTERM: ssh.SIGTERM,
	syscall.SIGUSR1: ssh.SIGUSR1,
	syscall.SIGUSR2: ssh.SIGUSR2,
}

// otherExitSignal names a signal outside the RFC 4254 list, as OpenSSH
// does; the message names the signal.
const otherExitSignal ssh.Signal = "SIG@openssh.com"

// sendShellExit reports how a shell process ended, given its Wait error:
// exit-status with its exit code, or exit-signal when a signal killed it.
// A Wait error that is not an exit is logged and reports failure.
func (s *Server) sendShellExit(ch ssh.Channel, err error) {
	if err == nil {
		sendExitStatus(ch, exitSuccess)
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		s.logger.Errorf("linux shell: %v", err)
		sendExitStatus(ch, exitFailure)
		return
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		sendExitSignal(ch, status.Signal(), status.CoreDump())
		return
	}
	sendExitStatus(ch, uint32(exitErr.ExitCode()))
}

// sendExitSignal reports that sig killed the session's shell (RFC 4254
// section 6.10): the signal name without the SIG prefix, whether it dumped
// core, a message and its language tag.
func sendExitSignal(ch ssh.Channel, sig syscall.Signal, coreDumped bool) {
	name, ok := exitSignalNames[sig]
	if !ok {
		name = otherExitSignal
	}
	msg := fmt.Sprintf("shell killed by signal %d (%s)", int(sig), sig)
	if coreDumped {
		msg += ", core dumped"
	}
	_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
		Signal     string
		CoreDumped bool
		Error      string
		Lang       string
	}{string(name), coreDumped, msg, "en"}))
}
