package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"encoding/json"

	"bytes"

	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/ids"
	"github.com/kballard/go-shellquote"
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
	r.Register("convert sigma", convertSigma)
	r.Register("help", helpCommand(r))
	r.Register("show help", showHelpCommand(r))
	r.Register("set help", setHelpCommand(r))
	if api != nil {
		r.Register("show health", showHealth(api))
		r.Register("show config", showConfig(api))
		r.Register("show running-config", showRunningConfig(api))
		r.Register("show candidate-config", showCandidateConfig(api))
		r.Register("show diff", showDiff(api))
		r.Register("show system", showSystem(api))
		r.Register("show services status", showServicesStatus(api))
		r.Register("show audit", showAudit(api))
		r.Register("show dataplane", showDataPlane(api))
		r.Register("show proxy forward", showForwardProxy(api))
		r.Register("show proxy reverse", showReverseProxy(api))
		r.Register("show flows", showFlows(api))
		r.Register("show events", showEvents(api))
		r.Register("show zones", showZonesAPI(api))
		r.Register("show interfaces", showInterfacesAPI(api))
		r.Register("show ids rules", showIDSRulesAPI(api))
		r.Register("set zone", setZoneAPI(api))
		r.Register("set interface", setInterfaceAPI(api))
		r.Register("set firewall rule", setFirewallRuleAPI(api))
		r.Register("delete firewall rule", deleteFirewallRuleAPI(api))
		r.Register("set dataplane", setDataPlaneAPI(api))
		r.Register("set system hostname", setSystemHostnameAPI(api))
		r.Register("set system mgmt listen", setSystemMgmtListenAPI(api))
		r.Register("set proxy forward", setForwardProxyAPI(api))
		r.Register("set proxy reverse", setReverseProxyAPI(api))
		r.Register("commit", commitAPI(api))
		r.Register("commit confirmed", commitConfirmedAPI(api))
		r.Register("confirm", confirmCommitAPI(api))
		r.Register("rollback", rollbackAPI(api))
		r.Register("export config", exportConfigAPI(api))
		r.Register("import config", importConfigAPI(api))
	} else if store != nil {
		r.Register("show zones", showZones(store))
		r.Register("show interfaces", showInterfaces(store))
	}
	return r
}

func convertSigma(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: convert sigma <sigma.yml> [more.yml...]")
	}
	return ids.WriteConvertedSigma(out, args)
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

// Commands returns available command names.
func (r *Registry) Commands() []string {
	if r == nil || r.commands == nil {
		return nil
	}
	out := make([]string, 0, len(r.commands))
	for k := range r.commands {
		out = append(out, k)
	}
	return out
}

// ParseAndExecute splits a CLI line (bash-style) and executes it.
// It matches the longest registered command prefix, passing remaining tokens as args.
func (r *Registry) ParseAndExecute(ctx context.Context, line string, out io.Writer) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	tokens, err := shellquote.Split(line)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return nil
	}
	name, args := matchCommand(tokens, r.Commands())
	if name == "" {
		return fmt.Errorf("unknown command: %s", tokens[0])
	}
	return r.Execute(ctx, name, out, args)
}

func matchCommand(tokens []string, available []string) (string, []string) {
	if len(tokens) == 0 {
		return "", nil
	}
	availSet := map[string]struct{}{}
	for _, a := range available {
		availSet[a] = struct{}{}
	}
	for i := len(tokens); i > 0; i-- {
		candidate := strings.ToLower(strings.Join(tokens[:i], " "))
		if _, ok := availSet[candidate]; ok {
			return candidate, tokens[i:]
		}
	}
	return "", nil
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

func showAudit(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var records []audit.Record
		if err := api.getJSON(ctx, "/api/v1/audit", &records); err != nil {
			return err
		}
		return printJSON(out, records)
	}
}

func showDataPlane(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var dp config.DataPlaneConfig
		if err := api.getJSON(ctx, "/api/v1/dataplane", &dp); err != nil {
			return err
		}
		return printJSON(out, dp)
	}
}

func showForwardProxy(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var fp config.ForwardProxyConfig
		if err := api.getJSON(ctx, "/api/v1/services/proxy/forward", &fp); err != nil {
			return err
		}
		return printJSON(out, fp)
	}
}

func showReverseProxy(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var rp config.ReverseProxyConfig
		if err := api.getJSON(ctx, "/api/v1/services/proxy/reverse", &rp); err != nil {
			return err
		}
		return printJSON(out, rp)
	}
}

func showFlows(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var flows []map[string]any
		if err := api.getJSON(ctx, "/api/v1/flows", &flows); err != nil {
			return err
		}
		return printJSON(out, flows)
	}
}

func showEvents(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var events []map[string]any
		if err := api.getJSON(ctx, "/api/v1/events", &events); err != nil {
			return err
		}
		return printJSON(out, events)
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

func setDataPlaneAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set dataplane enforcement on|off [table] [ifaces...]
		if len(args) < 2 {
			return fmt.Errorf("usage: set dataplane enforcement <on|off> [table] [iface...]")
		}
		if args[0] != "enforcement" {
			return fmt.Errorf("usage: set dataplane enforcement <on|off> [table] [iface...]")
		}
		on := args[1] == "on" || args[1] == "true" || args[1] == "1"
		dp := config.DataPlaneConfig{Enforcement: on}
		if len(args) > 2 {
			dp.EnforceTable = args[2]
		}
		if len(args) > 3 {
			dp.CaptureInterfaces = args[3:]
		}
		return api.postJSON(ctx, "/api/v1/dataplane", dp, out)
	}
}

func setForwardProxyAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set proxy forward <on|off> [port] [zone...]
		if len(args) < 1 {
			return fmt.Errorf("usage: set proxy forward <on|off> [port] [zone...]")
		}
		on := args[0] == "on" || args[0] == "true" || args[0] == "1"
		fp := config.ForwardProxyConfig{Enabled: on}
		if len(args) > 1 {
			port, err := strconv.Atoi(args[1])
			if err != nil || port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port: %s", args[1])
			}
			fp.ListenPort = port
		}
		if len(args) > 2 {
			fp.ListenZones = args[2:]
		}
		return api.postJSON(ctx, "/api/v1/services/proxy/forward", fp, out)
	}
}

func setReverseProxyAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set proxy reverse <on|off>
		if len(args) < 1 {
			return fmt.Errorf("usage: set proxy reverse <on|off>")
		}
		on := args[0] == "on" || args[0] == "true" || args[0] == "1"
		rp := config.ReverseProxyConfig{Enabled: on}
		return api.postJSON(ctx, "/api/v1/services/proxy/reverse", rp, out)
	}
}

func commitAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.postJSON(ctx, "/api/v1/config/commit", map[string]any{}, out)
	}
}

func commitConfirmedAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		payload := map[string]any{}
		if len(args) > 0 {
			ttl, err := strconv.Atoi(args[0])
			if err != nil || ttl <= 0 {
				return fmt.Errorf("usage: commit confirmed <ttl_seconds>")
			}
			payload["ttl_seconds"] = ttl
		}
		return api.postJSON(ctx, "/api/v1/config/commit_confirmed", payload, out)
	}
}

func confirmCommitAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.postJSON(ctx, "/api/v1/config/confirm", map[string]any{}, out)
	}
}

func rollbackAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.postJSON(ctx, "/api/v1/config/rollback", map[string]any{}, out)
	}
}

func exportConfigAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config/export", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func importConfigAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: import config <path>")
		}
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var cfg config.Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		return api.postJSON(ctx, "/api/v1/config/import", cfg, out)
	}
}

func printJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
