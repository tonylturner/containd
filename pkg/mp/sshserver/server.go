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
	ListenAddr          string
	BaseURL             string
	HostKeyPath         string
	AuthorizedKeysDir   string
	AllowPassword       bool
	Banner              string
	HostKeyRotationDays int
	LabMode             bool
	// ShellMode controls the default SSH login experience.
	// "linux": drops into a real bash shell; "appliance" (default): the CLI REPL.
	ShellMode           string
	JWTSecret           []byte
	// AllowLocalIP can reject connections based on the destination/local IP.
	// When nil, all destination IPs are allowed.
	AllowLocalIP func(ip net.IP) bool

	UserStore  users.Store
	AuditStore audit.Store
}

type Server struct {
	opts   Options
	logger *zap.SugaredLogger

	ln net.Listener
	wg sync.WaitGroup

	pwLimiter *ratelimit.AttemptLimiter
}

func New(opts Options) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, errors.New("ssh listen addr required")
	}
	if opts.BaseURL == "" {
		return nil, errors.New("ssh baseURL required")
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
		opts:      opts,
		logger:    logging.NewService("ssh"),
		pwLimiter: ratelimit.NewAttemptLimiter(1*time.Minute, 10, 2*time.Minute),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	signer, err := ensureHostKey(s.opts.HostKeyPath, s.opts.HostKeyRotationDays)
	if err != nil {
		return err
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback:  s.passwordCallback(),
		PublicKeyCallback: s.publicKeyCallback(),
		BannerCallback: func(conn ssh.ConnMetadata) string {
			if s.opts.Banner != "" {
				return s.opts.Banner + "\r\n"
			}
			return "containd ICS/OT firewall\r\n"
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.logger.Infof("ssh listening on %s", s.opts.ListenAddr)

	go func() {
		<-ctx.Done()
		_ = s.Close()
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
		go func(conn net.Conn) {
			defer s.wg.Done()
			s.handleConn(conn, cfg)
		}(c)
	}
	s.wg.Wait()
	return nil
}

func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handleConn(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()

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

	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
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

	connCtx := context.Background()
	token, sessionID, err := s.issueToken(connCtx, username, userID)
	if err != nil {
		_ = sc.Close()
		return
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

	api := &cli.API{BaseURL: s.opts.BaseURL, Token: token}
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
			}
			return
		case "exec":
			var m execMsg
			_ = ssh.Unmarshal(req.Payload, &m)
			_ = req.Reply(true, nil)
			line := strings.TrimSpace(m.Command)
			if line == "" {
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
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
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
			s.runMenu(ctx, username, rw, reader, reg)
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
	}
}
