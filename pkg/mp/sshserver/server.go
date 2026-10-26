// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type Options struct {
	ListenAddr string
	// CLI sessions call the management API at BaseURL with APIClient,
	// adding the X-Containd-SSH-Connection header to every request.
	BaseURL             string
	APIClient           cli.HTTPClient
	HostKeyPath         string
	AuthorizedKeysDir   string
	AllowPassword       bool
	Banner              string
	HostKeyRotationDays int
	// HostKeyRotationDaysFunc reads the running setting at each bounded check.
	HostKeyRotationDaysFunc func(context.Context) (int, error)
	// AuthPolicy reads the effective password setting and authorized-keys directory
	// together. Nil uses AllowPassword and AuthorizedKeysDir.
	AuthPolicy func(context.Context) (bool, string, error)
	LabMode    bool
	// ShellMode controls the default SSH login experience.
	// "linux": drops into a real bash shell; "appliance" (default): the CLI REPL.
	ShellMode string
	JWTSecret []byte
	// AllowLocalIP can reject connections based on the destination/local IP.
	// When nil, all destination IPs are allowed.
	AllowLocalIP func(ip net.IP) bool

	UserStore  users.Store
	AuditStore audit.Store
}

type Server struct {
	opts   Options
	logger *zap.SugaredLogger

	lnMu sync.Mutex
	ln   net.Listener
	wg   sync.WaitGroup

	hostKeyClock hostKeyClock

	pwLimiter *ratelimit.AttemptLimiter
	connMu    sync.Mutex
	conns     map[*sshConnection]struct{}
}

func New(opts Options) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, errors.New("ssh listen addr required")
	}
	if opts.BaseURL == "" {
		return nil, errors.New("ssh baseURL required")
	}
	if opts.APIClient == nil {
		return nil, errors.New("ssh API client required")
	}
	if opts.UserStore == nil {
		return nil, errors.New("user store required")
	}
	if !opts.LabMode && len(opts.JWTSecret) == 0 {
		return nil, errors.New("JWT secret required when not in lab mode")
	}
	if opts.HostKeyPath == "" {
		return nil, errors.New("host key path required")
	}
	if opts.AuthorizedKeysDir == "" {
		return nil, errors.New("authorized keys dir required")
	}
	return &Server{
		opts:         opts,
		logger:       logging.NewService("ssh"),
		pwLimiter:    ratelimit.NewAttemptLimiter(1*time.Minute, 10, 2*time.Minute),
		hostKeyClock: realHostKeyClock(),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	days, err := s.rotationDays(ctx)
	if err != nil {
		return err
	}
	signer, err := ensureHostKeyAt(s.opts.HostKeyPath, days, s.hostKeyClock.now())
	if err != nil {
		return err
	}

	// handleConn adds the PublicKeyCallback, which collects one connection's
	// refused keys.
	cfg := &ssh.ServerConfig{
		PasswordCallback:          s.passwordCallback(),
		VerifiedPublicKeyCallback: s.verifiedPublicKeyCallback(),
		BannerCallback: func(conn ssh.ConnMetadata) string {
			if s.opts.Banner != "" {
				return s.opts.Banner + "\r\n"
			}
			return "containd ICS/OT firewall\r\n"
		},
	}
	var current atomic.Pointer[ssh.ServerConfig]
	current.Store(configWithHostKey(cfg, signer))

	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()
	s.logger.Infof("ssh listening on %s", s.opts.ListenAddr)
	if !s.opts.LabMode {
		defer s.opts.UserStore.SubscribeSessionRevocations(s.closeRevokedSessions)()
	}

	lifetime, cancel := context.WithCancel(ctx)
	workersDone := make(chan struct{})
	defer func() { cancel(); <-workersDone }()
	go func() {
		defer close(workersDone)
		rotationDone := make(chan struct{})
		go func() {
			defer close(rotationDone)
			s.rotateHostKeys(lifetime, cfg, &current)
		}()
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-lifetime.Done():
		}
		<-rotationDone
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			s.logger.Errorf("accept error: %v", err)
			continue
		}
		s.wg.Add(1)
		go func(conn net.Conn, connConfig *ssh.ServerConfig) {
			defer s.wg.Done()
			s.handleConn(conn, connConfig)
		}(c, current.Load())
	}
	cancel()
	s.wg.Wait()
	return nil
}

func (s *Server) Close() error {
	s.RevokeConnections("")
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handleConn(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := s.trackConnection(nc, cancel)
	defer s.untrackConnection(conn)
	connCtx = context.WithValue(connCtx, connectionContextKey{}, conn)

	if s.opts.AllowLocalIP != nil {
		host, _, err := net.SplitHostPort(nc.LocalAddr().String())
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				if !s.opts.AllowLocalIP(ip) {
					return
				}
			}
		}
	}

	refusals := &keyRefusals{}
	connCfg := *cfg
	connCfg.PublicKeyCallback = s.publicKeyCallback(refusals)
	sc, chans, reqs, err := ssh.NewServerConn(nc, &connCfg)
	if err != nil {
		s.recordKeyRefusals(refusals)
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)

	username := sc.User()
	remote := sc.RemoteAddr().String()

	var userID string
	if sc.Permissions != nil {
		userID = sc.Permissions.Extensions["user_id"]
	}

	token, sessionID, err := s.issueToken(connCtx, username, userID)
	if err != nil {
		_ = sc.Close()
		return
	}
	s.connMu.Lock()
	conn.sessionID = sessionID
	s.connMu.Unlock()
	if sessionID != "" {
		// Credential changes made by this connection keep its own session.
		connCtx = users.WithActingSession(connCtx, sessionID)
	}
	if s.opts.AuditStore != nil {
		_ = s.opts.AuditStore.Add(connCtx, audit.Record{
			Actor:  username,
			Source: "ssh",
			Action: "ssh.login",
			Target: remote,
			Result: "success",
		})
	}

	api := &cli.API{BaseURL: s.opts.BaseURL, Token: token, Client: &resetAwareClient{client: s.opts.APIClient, connection: conn}}
	reg := cli.NewRegistry(nil, api)
	cmdCtx := cli.WithRole(connCtx, string(cli.RoleAdmin))

	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer channel.Close()
			s.handleSession(cmdCtx, username, remote, reg, channel, requests)
		}()
	}

	if sessionID != "" {
		_ = s.opts.UserStore.RevokeSession(context.Background(), sessionID)
	}
	if s.opts.AuditStore != nil {
		_ = s.opts.AuditStore.Add(context.Background(), audit.Record{
			Actor:  username,
			Source: "ssh",
			Action: "ssh.logout",
			Target: remote,
			Result: "success",
		})
	}
}

func (s *Server) handleSession(ctx context.Context, username, remote string, reg *cli.Registry, ch ssh.Channel, in <-chan *ssh.Request) {
	defer func() {
		if conn := connectionFromContext(ctx); conn != nil && conn.reset.Load() {
			conn.close()
		}
	}()
	type execMsg struct {
		Command string
	}

	var pr ptyRequest
	hasPTY := false
	// Channel for forwarding window-change events to the REPL (for inline shell).
	windowCh := make(chan ptyRequest, 4)
	defer close(windowCh)

	for req := range in {
		switch req.Type {
		case "pty-req":
			if parsed, ok := parsePtyReq(req.Payload); ok {
				pr = parsed
				hasPTY = true
			}
			_ = req.Reply(true, nil)
		case "window-change":
			if w, h, ok := parseWindowChange(req.Payload); ok {
				pr.Width = w
				pr.Height = h
				select {
				case windowCh <- ptyRequest{Width: w, Height: h}:
				default:
				}
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			_ = req.Reply(true, nil)
			if s.isLinuxShellMode() && hasPTY {
				s.startLinuxShell(ctx, username, ch, in, &pr)
			} else {
				if s.isLinuxShellMode() && !hasPTY {
					writeTTY(ch, "Warning: no PTY requested, falling back to appliance CLI.\n")
				}
				s.repl(ctx, username, remote, reg, ch, &pr, windowCh)
				sendExitStatus(ch, exitSuccess)
			}
			return
		case "exec":
			var m execMsg
			_ = ssh.Unmarshal(req.Payload, &m)
			_ = req.Reply(true, nil)
			line := strings.TrimSpace(m.Command)
			if line == "" {
				writeTTY(ch, "no command given\n")
				sendExitStatus(ch, exitFailure)
				return
			}
			var buf strings.Builder
			err := reg.ParseAndExecute(ctx, line, &buf)
			if s.opts.AuditStore != nil {
				rec := audit.Record{
					Actor:  username,
					Source: "ssh",
					Action: "cli.execute",
					Target: line,
					Result: "success",
					Detail: remote,
				}
				if err != nil {
					rec.Result = "failure"
					rec.Detail = err.Error()
				}
				_ = s.opts.AuditStore.Add(ctx, rec)
			}
			if buf.Len() > 0 {
				writeTTY(ch, buf.String())
				if !strings.HasSuffix(buf.String(), "\n") && !strings.HasSuffix(buf.String(), "\r\n") {
					writeTTY(ch, "\n")
				}
			}
			if err != nil {
				writeTTY(ch, err.Error()+"\n")
			}
			s.writeResetResult(ctx, ch)
			if err != nil {
				sendExitStatus(ch, exitFailure)
			} else {
				sendExitStatus(ch, exitSuccess)
			}
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

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

func (s *Server) isLinuxShellMode() bool {
	return strings.EqualFold(s.opts.ShellMode, "linux")
}

func (s *Server) repl(ctx context.Context, username, remote string, reg *cli.Registry, rw io.ReadWriter, pr *ptyRequest, windowCh <-chan ptyRequest) {
	reader := bufio.NewReader(rw)
	prompt := "containd# "
	// Gentle bootstrap hint.
	writeTTY(rw, "Type 'menu' for setup/diagnostics, or 'help'.\n")
	for {
		_, _ = io.WriteString(rw, "\r"+prompt)
		line, ok := readLineInteractive(reader, rw)
		if !ok {
			return
		}
		line = strings.TrimSpace(line)
		if line == "\x03" { // Ctrl-C
			writeTTY(rw, "^C\n")
			continue
		}
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "exit", "quit", "logout":
			return
		case "shell", "bash":
			if ch, ok := rw.(ssh.Channel); ok && pr != nil {
				s.startLinuxShellInline(ctx, username, ch, pr, windowCh)
				continue
			}
			writeTTY(rw, "shell access requires a PTY-enabled SSH session\n")
			continue
		case "menu":
			if s.runMenu(ctx, username, rw, reader, reg) {
				return
			}
			continue
		case "diagnostics", "diag":
			s.runDiagnosticsMenu(ctx, rw, reader, reg)
			continue
		case "wizard", "configure":
			s.runWizard(ctx, username, rw, reader, reg)
			continue
		}
		var buf strings.Builder
		err := reg.ParseAndExecute(ctx, line, &buf)
		if s.opts.AuditStore != nil {
			rec := audit.Record{
				Actor:  username,
				Source: "ssh",
				Action: "cli.execute",
				Target: line,
				Result: "success",
				Detail: remote,
			}
			if err != nil {
				rec.Result = "failure"
				rec.Detail = err.Error()
			}
			_ = s.opts.AuditStore.Add(ctx, rec)
		}
		if buf.Len() > 0 {
			writeTTY(rw, buf.String())
			if !strings.HasSuffix(buf.String(), "\n") && !strings.HasSuffix(buf.String(), "\r\n") {
				writeTTY(rw, "\n")
			}
		}
		if err != nil {
			writeTTY(rw, err.Error()+"\n")
		}
		if s.writeResetResult(ctx, rw) {
			return
		}
		if conn := connectionFromContext(ctx); conn != nil && conn.reset.Load() {
			return
		}
	}
}
