// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
)

func helpCommand(r *Registry) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		cmds := r.Commands()
		sort.Strings(cmds)
		showCmds, setCmds, other := splitByPrefix(cmds)

		fmt.Fprintln(out, "Available commands:")
		if len(showCmds) > 0 {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "show ...")
			for _, c := range showCmds {
				fmt.Fprintf(out, "  %s\n", c)
			}
			fmt.Fprintln(out, "  show help")
		}
		if len(setCmds) > 0 {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "set ...")
			for _, c := range setCmds {
				fmt.Fprintf(out, "  %s\n", c)
			}
			fmt.Fprintln(out, "  set help")
		}
		if len(other) > 0 {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "other")
			for _, c := range other {
				fmt.Fprintf(out, "  %s\n", c)
			}
		}
		fmt.Fprintln(out, "")
		// Danger zone.
		for _, c := range other {
			if c == "factory reset" {
				fmt.Fprintln(out, "Danger:")
				fmt.Fprintln(out, "  - factory reset NUCLEAR  (wipes config/users/audit and re-seeds default admin)")
				fmt.Fprintln(out, "")
				break
			}
		}
		fmt.Fprintln(out, "Tips:")
		fmt.Fprintln(out, "  - Commands are appliance-style and match longest prefix.")
		fmt.Fprintln(out, "  - Use quotes for arguments with spaces.")
		fmt.Fprintln(out, "  - ICS add/set: --message-class autonomous|session requires DNP3 or IEC 104 and --direction request|response (autonomous: response).")
		fmt.Fprintln(out, "  - In enforce, an ordinary ALLOW permits requests and paired solicited replies, not autonomous data or session controls.")
		fmt.Fprintln(out, "  - preview firewall ics-rule <id> <action> <protocol> [selectors] reports predicate matches separately from retained pairing outcomes; neither proves delivery.")
		fmt.Fprintln(out, "  - preview firewall ruleset reports the candidate ruleset and cutover warnings without applying it.")
		return nil
	}
}

func showHelpCommand(r *Registry) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		cmds := r.Commands()
		sort.Strings(cmds)
		showCmds, _, _ := splitByPrefix(cmds)
		if len(showCmds) == 0 {
			fmt.Fprintln(out, "No show commands registered.")
			return nil
		}
		fmt.Fprintln(out, "show commands:")
		for _, c := range showCmds {
			fmt.Fprintf(out, "  %s\n", c)
		}
		return nil
	}
}

func setHelpCommand(r *Registry) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		cmds := r.Commands()
		sort.Strings(cmds)
		_, setCmds, _ := splitByPrefix(cmds)
		if len(setCmds) == 0 {
			fmt.Fprintln(out, "No set commands registered.")
			return nil
		}
		fmt.Fprintln(out, "set commands:")
		for _, c := range setCmds {
			fmt.Fprintf(out, "  %s\n", c)
		}
		return nil
	}
}

func splitByPrefix(cmds []string) (showCmds, setCmds, other []string) {
	for _, c := range cmds {
		switch {
		case c == "help" || c == "show help" || c == "set help":
			continue
		case strings.HasPrefix(c, "show "):
			showCmds = append(showCmds, c)
		case strings.HasPrefix(c, "set "):
			setCmds = append(setCmds, c)
		default:
			other = append(other, c)
		}
	}
	return showCmds, setCmds, other
}
