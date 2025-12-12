package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"encoding/json"

	"bytes"

	"github.com/containd/containd/pkg/cp/config"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// API wraps HTTP interactions with the management plane.
type API struct {
	BaseURL string
	Client  HTTPClient
	Token   string
}

func (a *API) getJSON(ctx context.Context, path string, into any) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

func (a *API) postJSON(ctx context.Context, path string, payload any, out io.Writer) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		_, _ = out.Write([]byte("ok\n"))
	}
	return nil
}

func (a *API) delete(ctx context.Context, path string, out io.Writer) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		_, _ = out.Write([]byte("ok\n"))
	}
	return nil
}

// Command is a simple handler signature for CLI commands.
type Command func(ctx context.Context, out io.Writer, args []string) error

// Registry holds available commands.
type Registry struct {
	commands map[string]Command
}

// NewRegistry initializes the command registry with built-in commands.
func NewRegistry(store config.Store, api *API) *Registry {
	r := &Registry{commands: map[string]Command{}}
	r.Register("show version", showVersion)
	if api != nil {
		r.Register("show health", showHealth(api))
		r.Register("show config", showConfig(api))
		r.Register("show zones", showZonesAPI(api))
		r.Register("show interfaces", showInterfacesAPI(api))
		r.Register("set zone", setZoneAPI(api))
		r.Register("set interface", setInterfaceAPI(api))
		r.Register("set firewall rule", setFirewallRuleAPI(api))
		r.Register("delete firewall rule", deleteFirewallRuleAPI(api))
	} else if store != nil {
		r.Register("show zones", showZones(store))
		r.Register("show interfaces", showInterfaces(store))
	}
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

func showHealth(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/health", &payload); err != nil {
			return err
		}
		return printJSON(out, payload)
	}
}

func showConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
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

func showZonesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var zones []config.Zone
		if err := api.getJSON(ctx, "/api/v1/zones", &zones); err != nil {
			return err
		}
		for _, z := range zones {
			if z.Description != "" {
				fmt.Fprintf(out, "%s - %s\n", z.Name, z.Description)
			} else {
				fmt.Fprintln(out, z.Name)
			}
		}
		return nil
	}
}

func showInterfacesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var ifaces []config.Interface
		if err := api.getJSON(ctx, "/api/v1/interfaces", &ifaces); err != nil {
			return err
		}
		for _, iface := range ifaces {
			fmt.Fprintf(out, "%s zone=%s addrs=%v\n", iface.Name, iface.Zone, iface.Addresses)
		}
		return nil
	}
}

func setZoneAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set zone <name> [description]")
		}
		z := config.Zone{Name: args[0]}
		if len(args) > 1 {
			z.Description = args[1]
		}
		return api.postJSON(ctx, "/api/v1/zones", z, out)
	}
}

func setInterfaceAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface <name> <zone> [cidr...]")
		}
		iface := config.Interface{
			Name:      args[0],
			Zone:      args[1],
			Addresses: args[2:],
		}
		return api.postJSON(ctx, "/api/v1/interfaces", iface, out)
	}
}

func setFirewallRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set firewall rule <id> <action> [src_zone] [dst_zone]")
		}
		rule := config.Rule{
			ID:     args[0],
			Action: config.Action(args[1]),
		}
		if len(args) > 2 {
			rule.SourceZones = []string{args[2]}
		}
		if len(args) > 3 {
			rule.DestZones = []string{args[3]}
		}
		return api.postJSON(ctx, "/api/v1/firewall/rules", rule, out)
	}
}

func deleteFirewallRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: delete firewall rule <id>")
		}
		path := "/api/v1/firewall/rules/" + args[0]
		return api.delete(ctx, path, out)
	}
}

func printJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
