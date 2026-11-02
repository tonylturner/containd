// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const SessionExit = "Leaving configuration CLI. Shared candidate changes are unchanged; nothing has been committed or discarded."

// SessionConfigure names the existing configuration interpreter, never a wizard.
func SessionConfigure(line string) (string, bool) {
	if strings.EqualFold(strings.TrimSpace(line), "configure") {
		return "Already in configuration CLI. Configuration edits are staged until commit.", true
	}
	return "", false
}

// SessionStatus is presentation only. It never supplies a mutation revision.
type SessionStatus struct {
	Known     bool
	Changed   bool
	Deadline  string
	Refreshed time.Time
	Error     string
}

func (s SessionStatus) Prompt(role string) string {
	if role == string(RoleView) {
		return "containd(view)> "
	}
	marker := "?"
	if s.Known {
		marker = ""
		if s.Changed {
			marker = "*"
		}
	}
	return "containd(config" + marker + ")# "
}

func (s SessionStatus) String() string {
	state := "Candidate status unavailable"
	if s.Known {
		state = "Candidate matches running"
		if s.Changed {
			state = "Pending changes"
		}
	}
	text := state + " · Shared candidate"
	if s.Deadline != "" {
		text += " · Confirmation pending until " + s.Deadline
	}
	if !s.Refreshed.IsZero() {
		text += " · Refreshed " + s.Refreshed.Format(time.RFC3339)
	}
	if s.Error != "" {
		text += " · " + sessionText(s.Error)
	}
	return text
}

func (a *API) SessionStatus(ctx context.Context) SessionStatus {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var diff struct {
		Changed *bool `json:"changed"`
		Pending *struct {
			Deadline string `json:"deadline"`
		} `json:"pendingConfirm"`
	}
	if err := a.getJSON(ctx, "/api/v1/config/diff", &diff); err != nil {
		return SessionStatus{Error: err.Error()}
	}
	if diff.Changed == nil {
		return SessionStatus{Error: "Invalid config diff response"}
	}
	status := SessionStatus{Known: true, Changed: *diff.Changed, Refreshed: time.Now()}
	if diff.Pending != nil {
		status.Deadline = diff.Pending.Deadline
	}
	return status
}

// SessionEntry obtains the authenticated identity, not the registry routing role.
func (a *API) SessionEntry(ctx context.Context) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var me struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	var cfg struct {
		System struct {
			Hostname string `json:"hostname"`
		} `json:"system"`
	}
	_ = a.getJSON(ctx, "/api/v1/auth/me", &me)
	_ = a.getJSON(ctx, "/api/v1/config", &cfg)
	if me.Username == "" {
		me.Username = "identity unavailable"
	}
	if me.Role == "" {
		me.Role = "role unavailable"
	}
	if cfg.System.Hostname == "" {
		cfg.System.Hostname = "appliance unavailable"
	}
	mode := "Configuration CLI"
	if me.Role == string(RoleView) {
		mode = "Read-only CLI"
	}
	return fmt.Sprintf("%s — %s · %s/%s. Configuration edits are staged in a shared candidate; show diff reviews them, commit applies them. Operational commands can act immediately. This is not an OS shell.",
		mode, sessionText(cfg.System.Hostname), sessionText(me.Username), sessionText(me.Role)), me.Role
}

func sessionText(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, text)
}

func SessionCommandError(line string, err error) error {
	if err == nil {
		return nil
	}
	if !strings.HasPrefix(err.Error(), "unknown command:") {
		return err
	}
	word := strings.Fields(strings.ToLower(line))
	if len(word) > 0 {
		switch word[0] {
		case "pwd", "ls", "cd", "cat", "id", "whoami", "tcpdump", "nft", "ip", "sh", "bash", "shell":
			return fmt.Errorf("%w. This is the configuration CLI, not Linux. Use show commands; open an SSH OS shell for Linux tools", err)
		}
	}
	return fmt.Errorf("%w; use help for available commands", err)
}
