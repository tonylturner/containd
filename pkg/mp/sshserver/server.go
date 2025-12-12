package sshserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cli"
	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/common/ratelimit"
	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/users"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

type Options struct {
	ListenAddr        string
	BaseURL           string
	HostKeyPath       string
	AuthorizedKeysDir string
	AllowPassword     bool
	LabMode           bool
	JWTSecret         []byte
	// AllowLocalIP can reject connections based on the destination/local IP.
	// When nil, all destination IPs are allowed.
	AllowLocalIP func(ip net.IP) bool

	UserStore  users.Store
	AuditStore audit.Store
}

type Server struct {
	opts   Options
	logger *log.Logger

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
		logger:    logging.New("[ssh]"),
		pwLimiter: ratelimit.NewAttemptLimiter(1*time.Minute, 10, 2*time.Minute),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	signer, err := ensureHostKey(s.opts.HostKeyPath)
	if err != nil {
		return err
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback:  s.passwordCallback(),
		PublicKeyCallback: s.publicKeyCallback(),
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.logger.Printf("ssh listening on %s", s.opts.ListenAddr)

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
			s.logger.Printf("accept error: %v", err)
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

	for req := range in {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			s.repl(ctx, username, remote, reg, ch)
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

func (s *Server) repl(ctx context.Context, username, remote string, reg *cli.Registry, rw io.ReadWriter) {
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

func (s *Server) runMenu(ctx context.Context, username string, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) {
	writeLn := func(msg string) { writeTTY(rw, msg+"\n") }

	exec := func(line string) bool {
		var out strings.Builder
		err := reg.ParseAndExecute(ctx, line, &out)
		if out.Len() > 0 {
			writeTTY(rw, out.String())
			if !strings.HasSuffix(out.String(), "\n") && !strings.HasSuffix(out.String(), "\r\n") {
				writeLn("")
			}
		}
		if err != nil {
			writeLn("error: " + err.Error())
			return false
		}
		return true
	}

	ask := func(prompt string) (string, bool) {
		_, _ = io.WriteString(rw, "\r"+prompt)
		line, ok := readLineInteractive(reader, rw)
		if !ok {
			return "", false
		}
		line = strings.TrimSpace(line)
		if line == "\x03" {
			writeLn("^C")
			return "", false
		}
		return line, true
	}

	for {
		writeLn("")
		writeLn("containd console menu")
		writeLn("")
		writeLn("0)  Logout")
		writeLn("1)  Setup wizard")
		writeLn("2)  Diagnostics")
		writeLn("3)  Assign interface (zone + addresses)")
		writeLn("4)  Show system")
		writeLn("5)  Show interfaces")
		writeLn("6)  Show ip route")
		writeLn("7)  Reset your password")
		writeLn("8)  Commit candidate config")
		writeLn("9)  Help")
		writeLn("")

		choice, ok := ask("Select option (0-9): ")
		if !ok {
			return
		}
		switch strings.TrimSpace(choice) {
		case "0":
			return
		case "1":
			s.runWizard(ctx, username, rw, reader, reg)
		case "2":
			s.runDiagnosticsMenu(ctx, rw, reader, reg)
		case "3":
			iface, ok := ask("Interface name (e.g. lan1): ")
			if !ok {
				continue
			}
			iface = strings.TrimSpace(iface)
			if iface == "" {
				writeLn("Interface name is required.")
				continue
			}
			zone, ok := ask("Zone (wan/dmz/lan/mgmt): ")
			if !ok {
				continue
			}
			zone = strings.TrimSpace(zone)
			if zone == "" {
				writeLn("Zone is required.")
				continue
			}
			addrs, ok := ask("Addresses (CIDRs, space-separated; blank for none): ")
			if !ok {
				continue
			}
			addrs = strings.TrimSpace(addrs)
			cmd := "set interface " + shellEscape(iface) + " " + shellEscape(zone)
			if addrs != "" {
				cmd += " " + addrs
			}
			_ = exec(cmd)
		case "4":
			_ = exec("show system")
		case "5":
			_ = exec("show interfaces")
		case "6":
			_ = exec("show ip route")
		case "7":
			pw, ok := ask("New password (blank to cancel): ")
			if !ok {
				continue
			}
			if pw == "" {
				writeLn("Cancelled.")
				continue
			}
			u, err := s.opts.UserStore.GetByUsername(ctx, username)
			if err != nil || u == nil {
				writeLn("error: failed to load user")
				continue
			}
			if err := s.opts.UserStore.SetPassword(ctx, u.ID, pw); err != nil {
				writeLn("error: " + err.Error())
				continue
			}
			if s.opts.AuditStore != nil {
				_ = s.opts.AuditStore.Add(ctx, audit.Record{
					Actor:  username,
					Source: "ssh",
					Action: "user.password.set",
					Target: username,
					Result: "success",
				})
			}
			writeLn("Password updated.")
		case "8":
			_ = exec("commit")
		case "9":
			_ = exec("help")
		default:
			writeLn("Unknown option.")
		}
	}
}

func (s *Server) runDiagnosticsMenu(ctx context.Context, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) {
	writeLn := func(msg string) { writeTTY(rw, msg+"\n") }

	exec := func(line string) bool {
		var out strings.Builder
		err := reg.ParseAndExecute(ctx, line, &out)
		if out.Len() > 0 {
			writeTTY(rw, out.String())
			if !strings.HasSuffix(out.String(), "\n") && !strings.HasSuffix(out.String(), "\r\n") {
				writeLn("")
			}
		}
		if err != nil {
			writeLn("error: " + err.Error())
			return false
		}
		return true
	}

	ask := func(prompt string) (string, bool) {
		_, _ = io.WriteString(rw, "\r"+prompt)
		line, ok := readLineInteractive(reader, rw)
		if !ok {
			return "", false
		}
		line = strings.TrimSpace(line)
		if line == "\x03" {
			writeLn("^C")
			return "", false
		}
		return line, true
	}

	for {
		writeLn("")
		writeLn("Diagnostics")
		writeLn("")
		writeLn("0)  Back")
		writeLn("1)  Ping host")
		writeLn("2)  Traceroute host")
		writeLn("3)  Capture pcap")
		writeLn("4)  Show ip route")
		writeLn("")

		choice, ok := ask("Select option (0-4): ")
		if !ok {
			return
		}
		switch strings.TrimSpace(choice) {
		case "0":
			return
		case "1":
			host, ok := ask("Host/IP: ")
			if !ok {
				continue
			}
			host = strings.TrimSpace(host)
			if host == "" {
				writeLn("Host required.")
				continue
			}
			_ = exec("diag ping " + shellEscape(host))
		case "2":
			host, ok := ask("Host/IP: ")
			if !ok {
				continue
			}
			host = strings.TrimSpace(host)
			if host == "" {
				writeLn("Host required.")
				continue
			}
			_ = exec("diag traceroute " + shellEscape(host))
		case "3":
			iface, ok := ask("Interface (e.g. eth0/wan/lan1): ")
			if !ok {
				continue
			}
			iface = strings.TrimSpace(iface)
			if iface == "" {
				writeLn("Interface required.")
				continue
			}
			secs, ok := ask("Seconds (default 10): ")
			if !ok {
				continue
			}
			secs = strings.TrimSpace(secs)
			file, ok := ask("Output file (blank for default /data/pcaps/...): ")
			if !ok {
				continue
			}
			file = strings.TrimSpace(file)

			cmd := "diag capture " + shellEscape(iface)
			if secs != "" {
				cmd += " " + shellEscape(secs)
			}
			if file != "" {
				if secs == "" {
					cmd += " 10"
				}
				cmd += " " + shellEscape(file)
			}
			_ = exec(cmd)
		case "4":
			_ = exec("show ip route")
		default:
			writeLn("Unknown option.")
		}
	}
}

func (s *Server) runWizard(ctx context.Context, username string, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) {
	writeLn := func(msg string) {
		writeTTY(rw, msg+"\n")
	}
	exec := func(line string) bool {
		var out strings.Builder
		err := reg.ParseAndExecute(ctx, line, &out)
		if out.Len() > 0 {
			writeTTY(rw, out.String())
			if !strings.HasSuffix(out.String(), "\n") && !strings.HasSuffix(out.String(), "\r\n") {
				writeLn("")
			}
		}
		if err != nil {
			writeLn("error: " + err.Error())
			return false
		}
		return true
	}
	ask := func(prompt string) (string, bool) {
		_, _ = io.WriteString(rw, "\r"+prompt)
		line, ok := readLineInteractive(reader, rw)
		if !ok {
			return "", false
		}
		line = strings.TrimSpace(line)
		if line == "\x03" { // Ctrl-C
			writeLn("^C")
			return "", false
		}
		return line, true
	}

	writeLn("")
	writeLn("containd setup wizard (text)")
	writeLn("This writes to candidate config; you can commit at the end.")
	writeLn("")

	// Show current system summary (best-effort).
	{
		var buf strings.Builder
		_ = reg.ParseAndExecute(ctx, "show system", &buf)
		if buf.Len() > 0 {
			writeLn("Current:")
			writeTTY(rw, buf.String())
			if !strings.HasSuffix(buf.String(), "\n") && !strings.HasSuffix(buf.String(), "\r\n") {
				writeLn("")
			}
			writeLn("")
		}
	}

	if v, ok := ask("Hostname (blank to keep): "); ok && v != "" {
		if !exec("set system hostname " + shellEscape(v)) {
			writeLn("Wizard cancelled.")
			return
		}
		writeLn("ok")
	} else if !ok {
		writeLn("Wizard cancelled.")
		return
	}

	if v, ok := ask("Mgmt listen addr (e.g. :8080) (blank to keep): "); ok && v != "" {
		if !exec("set system mgmt listen " + shellEscape(v)) {
			writeLn("Wizard cancelled.")
			return
		}
		writeLn("ok")
	} else if !ok {
		writeLn("Wizard cancelled.")
		return
	}

	if v, ok := ask("SSH listen addr (e.g. :2222) (blank to keep): "); ok && v != "" {
		if !exec("set system ssh listen " + shellEscape(v)) {
			writeLn("Wizard cancelled.")
			return
		}
		writeLn("ok")
	} else if !ok {
		writeLn("Wizard cancelled.")
		return
	}

	if v, ok := ask("SSH authorized keys dir (blank to keep): "); ok && v != "" {
		if !exec("set system ssh authorized-keys-dir " + shellEscape(v)) {
			writeLn("Wizard cancelled.")
			return
		}
		writeLn("ok")
	} else if !ok {
		writeLn("Wizard cancelled.")
		return
	}

	if v, ok := ask("Enable SSH password auth? (yes/no, blank to keep): "); ok && v != "" {
		v = strings.ToLower(v)
		if v == "y" || v == "yes" {
			if !exec("set system ssh allow-password true") {
				writeLn("Wizard cancelled.")
				return
			}
			writeLn("ok")
		} else if v == "n" || v == "no" {
			if !exec("set system ssh allow-password false") {
				writeLn("Wizard cancelled.")
				return
			}
			writeLn("ok")
		}
	} else if !ok {
		writeLn("Wizard cancelled.")
		return
	}

	// Password change (direct store) - optional.
	if v, ok := ask("Set a new password for this user now? (blank to skip): "); ok {
		if v != "" {
			u, err := s.opts.UserStore.GetByUsername(ctx, username)
			if err == nil && u != nil {
				_ = s.opts.UserStore.SetPassword(ctx, u.ID, v)
				if s.opts.AuditStore != nil {
					_ = s.opts.AuditStore.Add(ctx, audit.Record{
						Actor:  username,
						Source: "ssh",
						Action: "user.password.set",
						Target: username,
						Result: "success",
					})
				}
				writeLn("password updated")
			} else {
				writeLn("failed to update password")
			}
		}
	} else {
		writeLn("Wizard cancelled.")
		return
	}

	if v, ok := ask("Commit changes now? (yes/no): "); ok {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "y" || v == "yes" {
			var buf strings.Builder
			err := reg.ParseAndExecute(ctx, "commit", &buf)
			if buf.Len() > 0 {
				writeTTY(rw, buf.String())
				if !strings.HasSuffix(buf.String(), "\n") && !strings.HasSuffix(buf.String(), "\r\n") {
					writeLn("")
				}
			}
			if err != nil {
				writeLn("error: " + err.Error())
				writeLn("Not committed. You can run: show diff  then commit")
			} else {
				writeLn("Committed. Note: changing listen addresses may require reconnecting.")
			}
		} else {
			writeLn("Not committed. You can review via 'show diff' then 'commit'.")
		}
	} else {
		writeLn("Wizard cancelled.")
		return
	}
	writeLn("")
}

func shellEscape(s string) string {
	// Minimal quoting for shellquote parsing: wrap in single quotes and escape existing ones.
	if s == "" {
		return "''"
	}
	if strings.IndexByte(s, '\'') == -1 {
		return "'" + s + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func readLine(r *bufio.Reader) (string, bool) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", false
		}
		// Ctrl-D (EOT) -> treat as EOF (exit session) if no input collected.
		if b == 0x04 && len(buf) == 0 {
			return "", false
		}
		// Ctrl-C (ETX) -> interrupt.
		if b == 0x03 {
			return "\x03", true
		}
		// Accept both \n and \r as line terminators (most SSH clients send \r).
		if b == '\n' || b == '\r' {
			break
		}
		buf = append(buf, b)
	}
	return string(buf), true
}

func readLineInteractive(r *bufio.Reader, echo io.Writer) (string, bool) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", false
		}
		// Ctrl-D (EOT) -> treat as EOF (exit session) if no input collected.
		if b == 0x04 && len(buf) == 0 {
			return "", false
		}
		// Ctrl-C (ETX) -> interrupt.
		if b == 0x03 {
			return "\x03", true
		}
		// Enter
		if b == '\n' || b == '\r' {
			writeTTY(echo, "\n")
			break
		}
		// Backspace / delete
		if b == 0x08 || b == 0x7f {
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				writeRaw(echo, "\b \b")
			}
			continue
		}
		// Ignore other control characters.
		if b < 0x20 {
			continue
		}
		buf = append(buf, b)
		writeRaw(echo, string([]byte{b}))
	}
	return string(buf), true
}

func writeTTY(w io.Writer, s string) {
	if w == nil || s == "" {
		return
	}
	// Normalize to CRLF for interactive terminals so each new line returns to column 0.
	n := strings.ReplaceAll(s, "\r\n", "\n")
	n = strings.ReplaceAll(n, "\r", "\n")
	n = strings.ReplaceAll(n, "\n", "\r\n")
	_, _ = io.WriteString(w, n)
}

func writeRaw(w io.Writer, s string) {
	if w == nil || s == "" {
		return
	}
	_, _ = io.WriteString(w, s)
}

func ensureHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, p, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(p)
}

func (s *Server) passwordCallback() func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if !s.opts.AllowPassword && !s.opts.LabMode {
			return nil, errors.New("password auth disabled")
		}
		key := conn.RemoteAddr().String() + "|" + strings.ToLower(conn.User())
		if s.pwLimiter != nil {
			if ok, _ := s.pwLimiter.Allow(key); !ok {
				return nil, errors.New("too many login attempts; retry later")
			}
		}
		u, err := s.opts.UserStore.GetByUsername(context.Background(), conn.User())
		if err != nil || u == nil {
			if s.pwLimiter != nil {
				s.pwLimiter.Fail(key)
			}
			return nil, errors.New("invalid credentials")
		}
		if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
			if s.pwLimiter != nil {
				s.pwLimiter.Fail(key)
			}
			return nil, errors.New("ssh requires admin role")
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), password) != nil {
			if s.pwLimiter != nil {
				s.pwLimiter.Fail(key)
			}
			return nil, errors.New("invalid credentials")
		}
		if s.pwLimiter != nil {
			s.pwLimiter.Success(key)
		}
		return &ssh.Permissions{Extensions: map[string]string{"user_id": u.ID}}, nil
	}
}

func (s *Server) publicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		u, err := s.opts.UserStore.GetByUsername(context.Background(), conn.User())
		if err != nil || u == nil {
			return nil, errors.New("invalid user")
		}
		if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
			return nil, errors.New("ssh requires admin role")
		}
		ok, err := isAuthorizedKey(s.opts.AuthorizedKeysDir, conn.User(), key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("unauthorized key")
		}
		return &ssh.Permissions{Extensions: map[string]string{"user_id": u.ID}}, nil
	}
}

func isAuthorizedKey(dir, username string, presented ssh.PublicKey) (bool, error) {
	candidates := []string{
		filepath.Join(dir, username),
		filepath.Join(dir, username+".pub"),
		filepath.Join(dir, username, "authorized_keys"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for len(b) > 0 {
			pub, _, _, rest, err := ssh.ParseAuthorizedKey(b)
			if err != nil {
				break
			}
			if bytes.Equal(pub.Marshal(), presented.Marshal()) {
				return true, nil
			}
			b = rest
		}
	}
	return false, nil
}

func (s *Server) issueToken(ctx context.Context, username, userID string) (token string, sessionID string, err error) {
	if s.opts.LabMode {
		return "lab", "", nil
	}
	u, err := s.opts.UserStore.GetByUsername(ctx, username)
	if err != nil || u == nil {
		return "", "", errors.New("user not found")
	}
	if userID != "" && u.ID != userID {
		return "", "", errors.New("user mismatch")
	}
	sess, err := s.opts.UserStore.CreateSession(ctx, u.ID, 5*time.Minute, 4*time.Hour)
	if err != nil {
		return "", "", err
	}
	tok, err := signJWT(s.opts.JWTSecret, u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
	if err != nil {
		_ = s.opts.UserStore.RevokeSession(ctx, sess.ID)
		return "", "", err
	}
	return tok, sess.ID, nil
}

func signJWT(secret []byte, userID string, username any, role any, jti string, exp time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub":      userID,
		"username": username,
		"role":     role,
		"jti":      jti,
		"iat":      time.Now().UTC().Unix(),
		"exp":      exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

func (s *Server) EnsureAuthorizedKeysDir() {
	_ = os.MkdirAll(s.opts.AuthorizedKeysDir, 0o700)
}

func (s *Server) SeedAuthorizedKey(username string, authorizedKeyLine string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username required")
	}
	line := strings.TrimSpace(authorizedKeyLine)
	if line == "" {
		return errors.New("authorized key required")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		return fmt.Errorf("invalid authorized key: %w", err)
	}

	if err := os.MkdirAll(s.opts.AuthorizedKeysDir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(s.opts.AuthorizedKeysDir, username+".pub")
	if b, err := os.ReadFile(dst); err == nil {
		if bytes.Contains(b, []byte(line)) {
			return nil
		}
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}
