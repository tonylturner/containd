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
	// base is the server configuration without host keys; current adds the
	// host key new connections use. Listen sets both; host key rotation
	// replaces current.
	base    *ssh.ServerConfig
	current atomic.Pointer[ssh.ServerConfig]
	wg      sync.WaitGroup

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

// Listen loads the host key and binds ListenAddr. The socket accepts no
// connection until Serve; Close releases it.
func (s *Server) Listen(ctx context.Context) error {
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
	base := &ssh.ServerConfig{
		PasswordCallback:          s.passwordCallback(),
		VerifiedPublicKeyCallback: s.verifiedPublicKeyCallback(),
		BannerCallback: func(conn ssh.ConnMetadata) string {
			if s.opts.Banner != "" {
				return s.opts.Banner + "\r\n"
			}
			return "containd ICS/OT firewall\r\n"
		},
	}
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if s.ln != nil {
		return errors.New("ssh server already listening")
	}
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.base = base
	s.current.Store(configWithHostKey(base, signer))
	s.logger.Infof("ssh listening on %s", ln.Addr())
	return nil
}

// Addr is the address of the socket Listen bound; nil before Listen.
func (s *Server) Addr() net.Addr {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve accepts connections on the socket Listen bound until ctx ends or
// Close is called. Call it once per Listen.
func (s *Server) Serve(ctx context.Context) error {
	s.lnMu.Lock()
	ln, base := s.ln, s.base
	s.lnMu.Unlock()
	if ln == nil {
		return errors.New("ssh server is not listening")
	}
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
			s.rotateHostKeys(lifetime, base, &s.current)
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
		}(c, s.current.Load())
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

	sessionID, err := s.openSession(connCtx, username, userID)
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
		s.audit(username, audit.Record{
			Actor:  username,
			Source: "ssh",
			Action: "ssh.login",
			Target: remote,
			Result: "success",
		})
	}

	client := s.connectionClient(conn)
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
		// Each channel owns its CLI client state; channels of one
		// connection share only the connection's management client.
		reg := cli.NewRegistry(nil, &cli.API{BaseURL: s.opts.BaseURL, Client: client})
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
		s.audit(username, audit.Record{
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
				// Without a client PTY the CLI has no terminal to give a shell.
				var shellPTY *ptyRequest
				if hasPTY {
					shellPTY = &pr
				}
				input := newSessionInput(ch)
				s.repl(ctx, username, remote, reg, &sessionIO{sessionInput: input, Writer: ch}, shellPTY, windowCh)
				input.close()
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
				s.audit(username, rec)
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

func (s *Server) isLinuxShellMode() bool {
	return strings.EqualFold(s.opts.ShellMode, "linux")
}

// repl runs the appliance CLI. pr is the client's PTY request, or nil when the
// client requested none; the shell command needs it.
func (s *Server) repl(ctx context.Context, username, remote string, reg *cli.Registry, rw *sessionIO, pr *ptyRequest, windowCh <-chan ptyRequest) {
	reader := bufio.NewReader(rw)
	ctx = newInteractiveSession(s, ctx, username, rw, reader, reg).secretContext(pr != nil)
	api := &cli.API{BaseURL: s.opts.BaseURL, Client: s.opts.APIClient}
	if conn := connectionFromContext(ctx); conn != nil {
		api.Client = s.connectionClient(conn)
	}
	entry, role := api.SessionEntry(ctx)
	writeTTY(rw, entry+"\nshell opens the Linux OS shell; exit disconnects SSH. menu and wizard are available here. Type help for commands.\n")
	defer writeTTY(rw, cli.SessionExit+"\nSSH disconnecting.\n")
	for {
		status := api.SessionStatus(ctx)
		writeTTY(rw, status.String()+"\n")
		_, _ = io.WriteString(rw, "\r"+status.Prompt(role))
		timer := time.NewTicker(5 * time.Second)
		typing := false
		rw.idle = timer.C
		rw.refresh = func() {
			status = api.SessionStatus(ctx)
			// Never erase partially entered input. Its next prompt uses fresh status.
			if !typing {
				writeTTY(rw, "\r\x1b[2K"+status.String()+"\n"+status.Prompt(role))
			}
		}
		line, ok := readTerminalLineProgress(reader, rw, true, func(nonempty bool) { typing = nonempty })
		rw.idle, rw.refresh = nil, nil
		timer.Stop()
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
		if output, handled := cli.SessionConfigure(line); handled {
			writeTTY(rw, output+"\n")
			continue
		}
		switch strings.ToLower(line) {
		case "exit", "quit", "logout":
			return
		case "shell":
			if pr != nil {
				s.startLinuxShellInline(ctx, username, rw, reader, pr, windowCh)
				continue
			}
			writeTTY(rw, "The Linux shell needs a terminal: reconnect with an interactive ssh session (not ssh -T).\n")
			continue
		case "menu":
			if s.runMenu(ctx, username, rw, reader, reg) {
				return
			}
			continue
		case "diagnostics", "diag":
			s.runDiagnosticsMenu(ctx, rw, reader, reg)
			continue
		case "wizard":
			s.runWizard(ctx, username, rw, reader, reg)
			continue
		}
		var buf strings.Builder
		err := cli.SessionCommandError(line, reg.ParseAndExecute(ctx, line, &buf))
		if strings.EqualFold(line, "help") {
			buf.WriteString("\nSSH controls: configure names this CLI; shell opens Linux (PTY required); menu, wizard, diagnostics; exit / quit / logout disconnect SSH.\n")
		}
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
			s.audit(username, rec)
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
