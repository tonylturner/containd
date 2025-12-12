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
		fmt.Fprintln(out, "Tips:")
		fmt.Fprintln(out, "  - Commands are appliance-style and match longest prefix.")
		fmt.Fprintln(out, "  - Use quotes for arguments with spaces.")
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
