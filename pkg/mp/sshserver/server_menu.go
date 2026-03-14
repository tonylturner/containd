// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"context"
	"io"
	"strings"

	"github.com/tonylturner/containd/pkg/cli"
)

func (s *Server) runMenu(ctx context.Context, username string, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) {
	session := newInteractiveSession(s, ctx, username, rw, reader, reg)
	for {
		session.renderMainMenu()
		choice, ok := session.ask("Select option (0-10): ")
		if !ok {
			return
		}
		if !session.handleMainMenuChoice(strings.TrimSpace(choice)) {
			return
		}
	}
}

func (s *interactiveSession) renderMainMenu() {
	s.writeLn("")
	s.writeLn("containd console menu")
	s.writeLn("")
	s.writeLn("0)  Logout")
	s.writeLn("1)  Assign interfaces (bind)")
	s.writeLn("2)  Set interface IP address")
	s.writeLn("3)  Reset admin password")
	s.writeLn("4)  Setup wizard")
	s.writeLn("5)  Diagnostics")
	s.writeLn("6)  Show system")
	s.writeLn("7)  Show interfaces")
	s.writeLn("8)  Show ip route")
	s.writeLn("9)  Help")
	s.writeLn("10) Factory reset (NUCLEAR)")
	s.writeLn("")
}

func (s *interactiveSession) handleMainMenuChoice(choice string) bool {
	switch choice {
	case "0":
		return false
	case "1":
		s.menuAssignInterfaces()
	case "2":
		s.menuSetInterfaceIP()
	case "3":
		s.menuResetPassword()
	case "4":
		s.runWizardFlow()
	case "5":
		s.server.runDiagnosticsMenu(s.ctx, s.rw, s.reader, s.reg)
	case "6":
		_ = s.exec("show system")
	case "7":
		_ = s.exec("show interfaces")
		_ = s.exec("show interfaces state")
	case "8":
		_ = s.exec("show ip route")
	case "9":
		_ = s.exec("help")
	case "10":
		return !s.menuFactoryReset()
	default:
		s.writeLn("Unknown option.")
	}
	return true
}

func (s *interactiveSession) menuAssignInterfaces() {
	_ = s.exec("show interfaces state")
	_ = s.exec("show interfaces")
	auto, ok := s.ask("Auto-assign defaults now? (yes/no): ")
	if !ok {
		return
	}
	auto = strings.ToLower(strings.TrimSpace(auto))
	if auto == "yes" || auto == "y" {
		_ = s.exec("assign interfaces auto")
		return
	}
	iface, ok := s.ask("Logical interface name (e.g. wan, dmz, lan1): ")
	if !ok {
		return
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		s.writeLn("Interface name is required.")
		return
	}
	dev, ok := s.ask("Kernel device (e.g. eth0) (blank to clear): ")
	if !ok {
		return
	}
	dev = strings.TrimSpace(dev)
	if dev == "" {
		dev = "none"
	}
	_ = s.exec("assign interfaces " + shellEscape(iface+"="+dev))
}

func (s *interactiveSession) menuSetInterfaceIP() {
	_ = s.exec("show interfaces")
	iface, ok := s.ask("Interface name (e.g. lan1): ")
	if !ok {
		return
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		s.writeLn("Interface name is required.")
		return
	}
	mode, ok := s.ask("Mode (static/dhcp) (blank=static): ")
	if !ok {
		return
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "static"
	}
	cmd := "set interface ip " + shellEscape(iface) + " " + shellEscape(mode)
	if mode == "dhcp" {
		_ = s.exec(cmd)
		return
	}
	cidr, ok := s.ask("CIDR (e.g. 192.168.1.2/24) (blank to clear): ")
	if !ok {
		return
	}
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		_ = s.exec("set interface ip " + shellEscape(iface) + " none")
		return
	}
	cmd += " " + shellEscape(cidr)
	gw, ok := s.ask("Gateway (optional, blank for none): ")
	if !ok {
		return
	}
	if gw = strings.TrimSpace(gw); gw != "" {
		cmd += " " + shellEscape(gw)
	}
	_ = s.exec(cmd)
}

func (s *interactiveSession) menuResetPassword() {
	pw, ok := s.ask("New password (blank to cancel): ")
	if !ok {
		return
	}
	if pw == "" {
		s.writeLn("Cancelled.")
		return
	}
	u, err := s.server.opts.UserStore.GetByUsername(s.ctx, s.username)
	if err != nil || u == nil {
		s.writeLn("error: failed to load user")
		return
	}
	if err := s.server.opts.UserStore.SetPassword(s.ctx, u.ID, pw); err != nil {
		s.writeLn("error: " + err.Error())
		return
	}
	s.writeAudit("user.password.set", s.username)
	s.writeLn("Password updated.")
}

func (s *interactiveSession) menuFactoryReset() bool {
	confirm, ok := s.ask("Type NUCLEAR to confirm factory reset: ")
	if !ok {
		return false
	}
	if strings.TrimSpace(confirm) != "NUCLEAR" {
		s.writeLn("Cancelled.")
		return false
	}
	_ = s.exec("factory reset NUCLEAR")
	s.writeLn("Factory reset complete. You will be logged out.")
	return true
}

func (s *Server) runDiagnosticsMenu(ctx context.Context, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) {
	session := newInteractiveSession(s, ctx, "", rw, reader, reg)
	for {
		session.renderDiagnosticsMenu()
		choice, ok := session.ask("Select option (0-5): ")
		if !ok {
			return
		}
		if !session.handleDiagnosticsChoice(strings.TrimSpace(choice)) {
			return
		}
	}
}

func (s *interactiveSession) renderDiagnosticsMenu() {
	s.writeLn("")
	s.writeLn("Diagnostics")
	s.writeLn("")
	s.writeLn("0)  Back")
	s.writeLn("1)  Ping host")
	s.writeLn("2)  Traceroute host (ICMP)")
	s.writeLn("3)  Traceroute host (TCP)")
	s.writeLn("4)  Capture pcap")
	s.writeLn("5)  Show ip route")
	s.writeLn("")
}

func (s *interactiveSession) handleDiagnosticsChoice(choice string) bool {
	switch choice {
	case "0":
		return false
	case "1":
		s.runDiagnosticPing()
	case "2":
		s.runDiagnosticTraceroute()
	case "3":
		s.runDiagnosticTCPTraceroute()
	case "4":
		s.runDiagnosticCapture()
	case "5":
		_ = s.exec("show ip route")
	default:
		s.writeLn("Unknown option.")
	}
	return true
}

func (s *interactiveSession) runDiagnosticPing() {
	host, ok := s.ask("Host/IP: ")
	if !ok {
		return
	}
	host = strings.TrimSpace(host)
	if host == "" {
		s.writeLn("Host required.")
		return
	}
	cnt, _ := s.ask("Count (default 4): ")
	cmd := "diag ping " + shellEscape(host)
	if cnt = strings.TrimSpace(cnt); cnt != "" {
		cmd += " " + shellEscape(cnt)
	}
	s.writeLn("Running... (may take a few seconds)")
	_ = s.exec(cmd)
}

func (s *interactiveSession) runDiagnosticTraceroute() {
	host, ok := s.ask("Host/IP: ")
	if !ok {
		return
	}
	host = strings.TrimSpace(host)
	if host == "" {
		s.writeLn("Host required.")
		return
	}
	hops, _ := s.ask("Max hops (default 10): ")
	cmd := "diag traceroute " + shellEscape(host)
	if hops = strings.TrimSpace(hops); hops != "" {
		cmd += " " + shellEscape(hops)
	} else {
		cmd += " 10"
	}
	s.writeLn("Running... (can take up to ~60s)")
	_ = s.exec(cmd)
}

func (s *interactiveSession) runDiagnosticTCPTraceroute() {
	host, ok := s.ask("Host/IP: ")
	if !ok {
		return
	}
	host = strings.TrimSpace(host)
	if host == "" {
		s.writeLn("Host required.")
		return
	}
	port, ok := s.ask("Port (e.g. 443): ")
	if !ok {
		return
	}
	port = strings.TrimSpace(port)
	if port == "" {
		s.writeLn("Port required.")
		return
	}
	hops, _ := s.ask("Max hops (default 10): ")
	cmd := "diag tcptraceroute " + shellEscape(host) + " " + shellEscape(port)
	if hops = strings.TrimSpace(hops); hops != "" {
		cmd += " " + shellEscape(hops)
	} else {
		cmd += " 10"
	}
	s.writeLn("Running... (can take up to ~60s)")
	_ = s.exec(cmd)
}

func (s *interactiveSession) runDiagnosticCapture() {
	iface, ok := s.ask("Interface (e.g. eth0/wan/lan1): ")
	if !ok {
		return
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		s.writeLn("Interface required.")
		return
	}
	secs, ok := s.ask("Seconds (default 10): ")
	if !ok {
		return
	}
	file, ok := s.ask("Output file (blank for default /data/pcaps/...): ")
	if !ok {
		return
	}
	cmd := "diag capture " + shellEscape(iface)
	if secs = strings.TrimSpace(secs); secs != "" {
		cmd += " " + shellEscape(secs)
	}
	if file = strings.TrimSpace(file); file != "" {
		if secs == "" {
			cmd += " 10"
		}
		cmd += " " + shellEscape(file)
	}
	s.writeLn("Running capture... (writes pcap to /data)")
	_ = s.exec(cmd)
}

func (s *Server) runWizard(ctx context.Context, username string, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) {
	newInteractiveSession(s, ctx, username, rw, reader, reg).runWizardFlow()
}

func (s *interactiveSession) runWizardFlow() {
	s.writeLn("")
	s.writeLn("containd setup wizard (text)")
	s.writeLn("This writes to candidate config; you can commit at the end.")
	s.writeLn("")
	s.showWizardCurrentSystem()

	if !s.wizardPromptSet("Hostname (blank to keep): ", "set system hostname ") {
		return
	}
	if !s.wizardPromptSet("Mgmt listen addr (e.g. :8080) (blank to keep): ", "set system mgmt listen ") {
		return
	}
	if !s.wizardPromptSet("SSH listen addr (e.g. :2222) (blank to keep): ", "set system ssh listen ") {
		return
	}
	if !s.wizardPromptSet("SSH authorized keys dir (blank to keep): ", "set system ssh authorized-keys-dir ") {
		return
	}
	if !s.wizardPromptSSHPasswordAuth() {
		return
	}
	if !s.wizardPromptPassword() {
		return
	}
	keyAdded, ok := s.wizardPromptSSHKey()
	if !ok {
		return
	}
	if keyAdded && !s.wizardPromptDisablePasswordAfterKey() {
		return
	}
	if !s.wizardPromptOutboundQuickstart() {
		return
	}
	if !s.wizardPromptCommit() {
		return
	}
	s.writeLn("")
}

func (s *interactiveSession) showWizardCurrentSystem() {
	buf, _ := s.execWithOutput("show system")
	if buf.Len() == 0 {
		return
	}
	s.writeLn("Current:")
	writeTTY(s.rw, buf.String())
	if !strings.HasSuffix(buf.String(), "\n") && !strings.HasSuffix(buf.String(), "\r\n") {
		s.writeLn("")
	}
	s.writeLn("")
}

func (s *interactiveSession) wizardPromptSet(prompt, cmdPrefix string) bool {
	v, ok := s.ask(prompt)
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false
	}
	if v == "" {
		return true
	}
	if !s.exec(cmdPrefix + shellEscape(v)) {
		s.writeLn("Wizard cancelled.")
		return false
	}
	s.writeLn("ok")
	return true
}

func (s *interactiveSession) wizardPromptSSHPasswordAuth() bool {
	v, ok := s.ask("Enable SSH password auth? (yes/no, blank to keep): ")
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "keep":
		return true
	case "y", "yes":
		if !s.exec("set system ssh allow-password true") {
			s.writeLn("Wizard cancelled.")
			return false
		}
		s.writeLn("ok")
	case "n", "no":
		if !s.exec("set system ssh allow-password false") {
			s.writeLn("Wizard cancelled.")
			return false
		}
		s.writeLn("ok")
	}
	return true
}

func (s *interactiveSession) wizardPromptPassword() bool {
	v, ok := s.ask("Set a new password for this user now? (blank to skip): ")
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false
	}
	if v == "" {
		return true
	}
	u, err := s.server.opts.UserStore.GetByUsername(s.ctx, s.username)
	if err == nil && u != nil {
		_ = s.server.opts.UserStore.SetPassword(s.ctx, u.ID, v)
		s.writeAudit("user.password.set", s.username)
		s.writeLn("password updated")
		return true
	}
	s.writeLn("failed to update password")
	return true
}

func (s *interactiveSession) wizardPromptSSHKey() (bool, bool) {
	v, ok := s.ask("Paste an SSH public key to enroll for this user (blank to skip): ")
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false, false
	}
	if strings.TrimSpace(v) == "" {
		return false, true
	}
	if err := s.server.SeedAuthorizedKey(s.username, v); err != nil {
		s.writeLn("error: failed to add key: " + err.Error())
		return false, true
	}
	s.writeLn("ssh key added")
	return true, true
}

func (s *interactiveSession) wizardPromptDisablePasswordAfterKey() bool {
	v, ok := s.ask("Disable SSH password auth now? (yes/no, blank to keep): ")
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "y" || v == "yes" {
		if !s.exec("set system ssh allow-password false") {
			s.writeLn("Wizard cancelled.")
			return false
		}
		s.writeLn("ok")
	}
	return true
}

func (s *interactiveSession) wizardPromptOutboundQuickstart() bool {
	v, ok := s.ask("Enable outbound Internet for LAN/MGMT → WAN now? (yes/no, blank to skip): ")
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "y" || v == "yes" {
		if s.exec("set outbound quickstart") {
			s.writeLn("ok")
		} else {
			s.writeLn("warning: outbound quick start failed (continuing)")
		}
	}
	return true
}

func (s *interactiveSession) wizardPromptCommit() bool {
	v, ok := s.ask("Commit changes now? (yes/no): ")
	if !ok {
		s.writeLn("Wizard cancelled.")
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v != "y" && v != "yes" {
		s.writeLn("Not committed. You can review via 'show diff' then 'commit'.")
		return true
	}
	_, err := s.execWithOutput("commit")
	if err != nil {
		s.writeLn("error: " + err.Error())
		s.writeLn("Not committed. You can run: show diff  then commit")
		return true
	}
	s.writeLn("Committed. Note: changing listen addresses may require reconnecting.")
	return true
}

func shellEscape(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexByte(s, '\'') == -1 {
		return "'" + s + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func readLineInteractive(r *bufio.Reader, echo io.Writer) (string, bool) {
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
			writeTTY(echo, "\n")
			break
		}
		if b == 0x08 || b == 0x7f {
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				writeRaw(echo, "\b \b")
			}
			continue
		}
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
