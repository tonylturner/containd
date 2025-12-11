package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/containd/containd/pkg/cp/config"
)

// Command is a simple handler signature for CLI commands.
type Command func(ctx context.Context, out io.Writer, args []string) error

// Registry holds available commands.
type Registry struct {
	commands map[string]Command
}

// NewRegistry initializes the command registry with built-in commands.
func NewRegistry(store config.Store) *Registry {
	r := &Registry{commands: map[string]Command{}}
	r.Register("show version", showVersion)
	r.Register("show zones", showZones(store))
	r.Register("show interfaces", showInterfaces(store))
	return r
}

// Register adds a command handler.
func (r *Registry) Register(name string, cmd Command) {
	if r.commands == nil {
		r.commands = map[string]Command{}
	}
	r.commands[name] = cmd
}

// Execute runs a command by full name.
func (r *Registry) Execute(ctx context.Context, name string, out io.Writer, args []string) error {
	cmd, ok := r.commands[name]
	if !ok {
		return fmt.Errorf("unknown command: %s", name)
	}
	return cmd(ctx, out, args)
}

func showVersion(ctx context.Context, out io.Writer, args []string) error {
	_, err := fmt.Fprintf(out, "containd ngfw-mgmt (dev)\n")
	return err
}

func showZones(store config.Store) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		cfg, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if len(cfg.Zones) == 0 {
			_, err = fmt.Fprintln(out, "No zones configured")
			return err
		}
		for _, z := range cfg.Zones {
			if z.Description != "" {
				fmt.Fprintf(out, "%s - %s\n", z.Name, z.Description)
			} else {
				fmt.Fprintln(out, z.Name)
			}
		}
		return nil
	}
}

func showInterfaces(store config.Store) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		cfg, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if len(cfg.Interfaces) == 0 {
			_, err = fmt.Fprintln(out, "No interfaces configured")
			return err
		}
		for _, iface := range cfg.Interfaces {
			fmt.Fprintf(out, "%s zone=%s addrs=%v\n", iface.Name, iface.Zone, iface.Addresses)
		}
		return nil
	}
}
