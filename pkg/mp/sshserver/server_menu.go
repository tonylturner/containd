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
	"github.com/tonylturner/containd/pkg/cp/users"
)

func (s *Server) runMenu(ctx context.Context, username string, rw io.ReadWriter, reader *bufio.Reader, reg *cli.Registry) bool {
	session := newInteractiveSession(s, ctx, username, rw, reader, reg)
	for {
		session.renderMainMenu()
		choice, ok := session.ask("containd(menu)> Select option (0-11): ")
		if !ok {
			return false
		}
		if choice == "11" || choice == "back" || choice == "exit" {
			return false
		}
		if !session.handleMainMenuChoice(strings.TrimSpace(choice)) {
			return true
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
	s.writeLn("3)  Change your password (immediate)")
	s.writeLn("4)  Setup wizard")
	s.writeLn("5)  Diagnostics")
	s.writeLn("6)  Show system")
	s.writeLn("7)  Show interfaces")
	s.writeLn("8)  Show ip route")
	s.writeLn("9)  Help")
	s.writeLn("10) Factory reset (NUCLEAR)")
	s.writeLn("11) Back to CLI (0 logs out of SSH)")
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
	if err := users.CheckPasswordChange(); err != nil {
		s.writeLn("error: " + err.Error())
		return
	}
	switch s.changeOwnPassword("ssh menu", "Current password (blank to cancel): ", "New password (blank to cancel): ") {
	case ownPasswordChanged:
		s.writeLn("Password updated.")
	case ownPasswordSkipped:
		s.writeLn("Cancelled.")
	}
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
	if !s.exec("factory reset NUCLEAR") {
		s.writeLn("Factory reset failed. Review the error before retrying.")
		if conn := connectionFromContext(s.ctx); conn != nil && conn.reset.Load() {
			s.writeLn("Authentication was revoked. You will be logged out.")
			return true
		}
		return false
	}
	if s.server.writeResetResult(s.ctx, s.rw) {
		return true
	}
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
	case "0", "back", "exit":
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
	s.writeLn("Config edits are staged as you answer; cancelling does not undo staged edits. Password/key changes apply immediately.")
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
	s.writeLn("Current:")
	_ = s.exec("show system")
	s.writeLn("")
}

func (s *interactiveSession) wizardPromptSet(prompt, cmdPrefix string) bool {
	v, ok := s.ask("containd(setup:candidate)> " + prompt)
	if !ok {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
		return false
	}
	if v == "" {
		return true
	}
	if !s.exec(cmdPrefix + shellEscape(v)) {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
		return false
	}
	s.writeLn("ok")
	return true
}

func (s *interactiveSession) wizardPromptSSHPasswordAuth() bool {
	v, ok := s.ask("containd(setup:candidate)> Enable SSH password auth? (yes/no, blank to keep): ")
	if !ok {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "keep":
		return true
	case "y", "yes":
		if !s.exec("set system ssh allow-password true") {
			s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
			return false
		}
		s.writeLn("ok")
	case "n", "no":
		if !s.exec("set system ssh allow-password false") {
			s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
			return false
		}
		s.writeLn("ok")
	}
	return true
}

func (s *interactiveSession) wizardPromptPassword() bool {
	if err := users.CheckPasswordChange(); err != nil {
		s.writeLn("password step skipped: " + err.Error())
		return true
	}
	switch s.changeOwnPassword("ssh setup wizard", "containd(setup:password-immediate)> Current password, to change it (blank to skip): ", "New password for this user: ") {
	case ownPasswordChanged:
		s.writeLn("password updated")
	case ownPasswordFailed:
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
		return false
	}
	return true
}

func (s *interactiveSession) wizardPromptSSHKey() (bool, bool) {
	v, ok := s.ask("containd(setup:key-immediate)> Paste an SSH public key to enroll for this user (blank to skip): ")
	if !ok {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
		return false, false
	}
	if strings.TrimSpace(v) == "" {
		return false, true
	}
	if err := s.server.SeedAuthorizedKey(s.username, v); err != nil {
		s.writeLn("error: failed to add key: " + err.Error())
		return false, true
	}
	s.writeAudit(audit.Record{Action: "ssh.authorized_key.add", Target: s.username, Detail: authorizedKeyFingerprint(v)})
	s.writeLn("ssh key added")
	return true, true
}

func (s *interactiveSession) wizardPromptDisablePasswordAfterKey() bool {
	v, ok := s.ask("containd(setup:candidate)> Stage disabling SSH password auth? (yes/no, blank to keep): ")
	if !ok {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "y" || v == "yes" {
		if !s.exec("set system ssh allow-password false") {
			s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
			return false
		}
		s.writeLn("ok")
	}
	return true
}

func (s *interactiveSession) wizardPromptOutboundQuickstart() bool {
	v, ok := s.ask("containd(setup:candidate)> Stage outbound Internet settings for LAN/MGMT → WAN? (yes/no, blank to skip): ")
	if !ok {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
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
	s.writeLn("Review the shared candidate, including edits from other sessions:")
	if !s.exec("show diff") {
		s.writeLn("Cannot review shared candidate; not committing.")
		return false
	}
	v, ok := s.ask("containd(setup:commit)> Commit changes now? (shared candidate, yes/no): ")
	if !ok {
		s.writeLn("Wizard cancelled. Earlier candidate edits remain staged; immediate changes are not undone.")
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
