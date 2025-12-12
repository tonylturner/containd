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

	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/cp/ids"
	dpevents "github.com/containd/containd/pkg/dp/events"
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

func (a *API) updateTokenFromResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	if tok := strings.TrimSpace(resp.Header.Get("X-Auth-Token")); tok != "" {
		a.Token = tok
	}
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
	a.updateTokenFromResponse(resp)
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
	a.updateTokenFromResponse(resp)
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		_, _ = out.Write([]byte("ok\n"))
	}
	return nil
}

func (a *API) patchJSON(ctx context.Context, path string, payload any, out io.Writer) error {
	if a.Client == nil {
		a.Client = http.DefaultClient
	}
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, a.BaseURL+path, buf)
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
	a.updateTokenFromResponse(resp)
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
	a.updateTokenFromResponse(resp)
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
	roles    map[string]Role
}

// NewRegistry initializes the command registry with built-in commands.
func NewRegistry(store config.Store, api *API) *Registry {
	r := &Registry{commands: map[string]Command{}, roles: map[string]Role{}}
	r.RegisterRole("show version", RoleView, showVersion)
	r.RegisterRole("convert sigma", RoleView, convertSigma)
	r.RegisterRole("help", RoleView, helpCommand(r))
	r.RegisterRole("show help", RoleView, showHelpCommand(r))
	r.RegisterRole("set help", RoleView, setHelpCommand(r))
	// Local diagnostics (available in SSH; may require CAP_NET_RAW for some features).
	r.RegisterRole("show ip route", RoleView, showIPRoute())
	r.RegisterRole("diag ping", RoleView, diagPing())
	r.RegisterRole("diag traceroute", RoleView, diagTraceroute())
	r.RegisterRole("diag capture", RoleAdmin, diagCapture())
	if api != nil {
		r.RegisterRole("show health", RoleView, showHealth(api))
		r.RegisterRole("show config", RoleView, showConfig(api))
		r.RegisterRole("show running-config", RoleView, showRunningConfig(api))
		r.RegisterRole("show running-config redacted", RoleView, showRunningConfigRedacted(api))
		r.RegisterRole("show candidate-config", RoleView, showCandidateConfig(api))
		r.RegisterRole("show diff", RoleView, showDiff(api))
		r.RegisterRole("show system", RoleView, showSystem(api))
		r.RegisterRole("show services status", RoleView, showServicesStatus(api))
		r.RegisterRole("show audit", RoleView, showAudit(api))
		r.RegisterRole("show dataplane", RoleView, showDataPlane(api))
		r.RegisterRole("show proxy forward", RoleView, showForwardProxy(api))
		r.RegisterRole("show proxy reverse", RoleView, showReverseProxy(api))
		r.RegisterRole("show flows", RoleView, showFlows(api))
		r.RegisterRole("show events", RoleView, showEvents(api))
		r.RegisterRole("show zones", RoleView, showZonesAPI(api))
		r.RegisterRole("show interfaces", RoleView, showInterfacesAPI(api))
		r.RegisterRole("show ids rules", RoleView, showIDSRulesAPI(api))
		r.RegisterRole("set zone", RoleAdmin, setZoneAPI(api))
		r.RegisterRole("set interface", RoleAdmin, setInterfaceAPI(api))
		r.RegisterRole("set interface zone", RoleAdmin, setInterfaceZoneAPI(api))
		r.RegisterRole("set interface ip", RoleAdmin, setInterfaceIPAPI(api))
		r.RegisterRole("set firewall rule", RoleAdmin, setFirewallRuleAPI(api))
		r.RegisterRole("delete firewall rule", RoleAdmin, deleteFirewallRuleAPI(api))
		r.RegisterRole("set dataplane", RoleAdmin, setDataPlaneAPI(api))
		r.RegisterRole("set system hostname", RoleAdmin, setSystemHostnameAPI(api))
		r.RegisterRole("set system mgmt listen", RoleAdmin, setSystemMgmtListenAPI(api))
		r.RegisterRole("set system mgmt http listen", RoleAdmin, setSystemMgmtHTTPListenAPI(api))
		r.RegisterRole("set system mgmt https listen", RoleAdmin, setSystemMgmtHTTPSListenAPI(api))
		r.RegisterRole("set system mgmt http enable", RoleAdmin, setSystemMgmtEnableHTTPAPI(api))
		r.RegisterRole("set system mgmt https enable", RoleAdmin, setSystemMgmtEnableHTTPSAPI(api))
		r.RegisterRole("set system mgmt redirect-http-to-https", RoleAdmin, setSystemMgmtRedirectHTTPToHTTPSAPI(api))
		r.RegisterRole("set system mgmt hsts", RoleAdmin, setSystemMgmtHSTSAPI(api))
		r.RegisterRole("set system ssh listen", RoleAdmin, setSystemSSHListenAPI(api))
		r.RegisterRole("set system ssh allow-password", RoleAdmin, setSystemSSHAllowPasswordAPI(api))
		r.RegisterRole("set system ssh authorized-keys-dir", RoleAdmin, setSystemSSHAuthorizedKeysDirAPI(api))
		r.RegisterRole("set proxy forward", RoleAdmin, setForwardProxyAPI(api))
		r.RegisterRole("set proxy reverse", RoleAdmin, setReverseProxyAPI(api))
		r.RegisterRole("commit", RoleAdmin, commitAPI(api))
		r.RegisterRole("commit confirmed", RoleAdmin, commitConfirmedAPI(api))
		r.RegisterRole("confirm", RoleAdmin, confirmCommitAPI(api))
		r.RegisterRole("rollback", RoleAdmin, rollbackAPI(api))
		r.RegisterRole("export config", RoleAdmin, exportConfigAPI(api))
		r.RegisterRole("import config", RoleAdmin, importConfigAPI(api))
	} else if store != nil {
		r.RegisterRole("show zones", RoleView, showZones(store))
		r.RegisterRole("show interfaces", RoleView, showInterfaces(store))
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
	if r.roles == nil {
		r.roles = map[string]Role{}
	}
	// Default to view access unless specified.
	if _, ok := r.roles[name]; !ok {
		r.roles[name] = RoleView
	}
}

// RegisterRole adds a command handler with an explicit minimum role.
func (r *Registry) RegisterRole(name string, role Role, cmd Command) {
	r.Register(name, cmd)
	if r.roles == nil {
		r.roles = map[string]Role{}
	}
	r.roles[name] = role
}

// Execute runs a command by full name.
func (r *Registry) Execute(ctx context.Context, name string, out io.Writer, args []string) error {
	cmd, ok := r.commands[name]
	if !ok {
		return fmt.Errorf("unknown command: %s", name)
	}
	required := RoleView
	if r.roles != nil {
		if v, ok := r.roles[name]; ok && v != "" {
			required = v
		}
	}
	have := roleFromContext(ctx)
	if !allowed(required, have) {
		return fmt.Errorf("%w: %s requires %s", ErrPermissionDenied, name, required)
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
		kv := map[string]string{}
		for k, v := range payload {
			kv[k] = fmtAny(v)
		}
		kvTable(out, kv)
		return nil
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
		if out == nil {
			return nil
		}
		if len(records) == 0 {
			fmt.Fprintln(out, "No audit records.")
			return nil
		}
		t := newTable("ID", "TIME", "ACTOR", "SOURCE", "ACTION", "TARGET", "RESULT", "DETAIL")
		for _, r := range records {
			t.addRow(
				fmt.Sprintf("%d", r.ID),
				fmtTime(r.Timestamp),
				truncate(r.Actor, 20),
				truncate(r.Source, 10),
				truncate(r.Action, 24),
				truncate(r.Target, 20),
				truncate(r.Result, 8),
				truncate(r.Detail, 40),
			)
		}
		t.render(out)
		return nil
	}
}

func showDataPlane(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var dp config.DataPlaneConfig
		if err := api.getJSON(ctx, "/api/v1/dataplane", &dp); err != nil {
			return err
		}
		kvTable(out, map[string]string{
			"captureInterfaces": joinCSV(dp.CaptureInterfaces),
			"enforcement":       yesNoStr(dp.Enforcement),
			"enforceTable":      firstNonEmpty(dp.EnforceTable, "containd"),
			"dpiMock":           yesNoStr(dp.DPIMock),
		})
		return nil
	}
}

func showForwardProxy(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var fp config.ForwardProxyConfig
		if err := api.getJSON(ctx, "/api/v1/services/proxy/forward", &fp); err != nil {
			return err
		}
		kvTable(out, map[string]string{
			"enabled":        yesNoStr(fp.Enabled),
			"listenPort":     fmtAny(fp.ListenPort),
			"listenZones":    joinCSV(fp.ListenZones),
			"allowedClients": joinCSV(fp.AllowedClients),
			"allowedDomains": joinCSV(fp.AllowedDomains),
			"upstream":       firstNonEmpty(fp.Upstream, "—"),
			"logRequests":    yesNoStr(fp.LogRequests),
		})
		return nil
	}
}

func showReverseProxy(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var rp config.ReverseProxyConfig
		if err := api.getJSON(ctx, "/api/v1/services/proxy/reverse", &rp); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		kvTable(out, map[string]string{
			"enabled": yesNoStr(rp.Enabled),
			"sites":   fmt.Sprintf("%d", len(rp.Sites)),
		})
		if len(rp.Sites) > 0 {
			t := newTable("NAME", "PORT", "HOSTNAMES", "BACKENDS", "TLS")
			for _, s := range rp.Sites {
				t.addRow(
					s.Name,
					fmt.Sprintf("%d", s.ListenPort),
					truncate(joinCSV(s.Hostnames), 40),
					truncate(joinCSV(s.Backends), 40),
					yesNoStr(s.TLSEnabled),
				)
			}
			fmt.Fprintln(out)
			t.render(out)
		}
		return nil
	}
}

func showFlows(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var flows []dpevents.FlowSummary
		if err := api.getJSON(ctx, "/api/v1/flows", &flows); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(flows) == 0 {
			fmt.Fprintln(out, "No flows.")
			return nil
		}
		t := newTable("FLOW", "SRC", "DST", "TRANSPORT", "APP", "FIRST", "LAST", "EVENTS")
		for _, f := range flows {
			src := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)
			dst := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
			t.addRow(
				truncate(f.FlowID, 12),
				truncate(src, 22),
				truncate(dst, 22),
				firstNonEmpty(f.Transport, "—"),
				firstNonEmpty(f.Application, "—"),
				fmtTime(f.FirstSeen),
				fmtTime(f.LastSeen),
				fmt.Sprintf("%d", f.EventCount),
			)
		}
		t.render(out)
		return nil
	}
}

func showEvents(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var events []dpevents.Event
		if err := api.getJSON(ctx, "/api/v1/events", &events); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(events) == 0 {
			fmt.Fprintln(out, "No events.")
			return nil
		}
		t := newTable("ID", "TIME", "FLOW", "PROTO", "KIND", "SRC", "DST", "ATTRS")
		for _, ev := range events {
			src := fmt.Sprintf("%s:%d", ev.SrcIP, ev.SrcPort)
			dst := fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)
			t.addRow(
				fmt.Sprintf("%d", ev.ID),
				fmtTime(ev.Timestamp),
				truncate(ev.FlowID, 12),
				ev.Proto,
				ev.Kind,
				truncate(src, 22),
				truncate(dst, 22),
				attrsSummary(ev.Attributes, 60),
			)
		}
		t.render(out)
		return nil
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
		t := newTable("NAME", "DESCRIPTION")
		for _, z := range cfg.Zones {
			t.addRow(z.Name, firstNonEmpty(z.Description, "—"))
		}
		t.render(out)
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
		t := newTable("NAME", "ZONE", "ADDRESSES")
		for _, iface := range cfg.Interfaces {
			t.addRow(iface.Name, firstNonEmpty(iface.Zone, "—"), joinCSV(iface.Addresses))
		}
		t.render(out)
		return nil
	}
}

func showZonesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var zones []config.Zone
		if err := api.getJSON(ctx, "/api/v1/zones", &zones); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(zones) == 0 {
			fmt.Fprintln(out, "No zones configured")
			return nil
		}
		t := newTable("NAME", "DESCRIPTION")
		for _, z := range zones {
			t.addRow(z.Name, firstNonEmpty(z.Description, "—"))
		}
		t.render(out)
		return nil
	}
}

func showInterfacesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var ifaces []config.Interface
		if err := api.getJSON(ctx, "/api/v1/interfaces", &ifaces); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(ifaces) == 0 {
			fmt.Fprintln(out, "No interfaces configured")
			return nil
		}
		t := newTable("NAME", "ZONE", "ADDRESSES")
		for _, iface := range ifaces {
			t.addRow(iface.Name, firstNonEmpty(iface.Zone, "—"), joinCSV(iface.Addresses))
		}
		t.render(out)
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

func setInterfaceZoneAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface zone <name> <zone>")
		}
		payload := config.Interface{Zone: args[1]}
		return api.patchJSON(ctx, "/api/v1/interfaces/"+args[0], payload, out)
	}
}

func setInterfaceIPAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface ip <name> <cidr...|none>")
		}
		addrs := args[1:]
		if len(addrs) == 1 {
			switch strings.ToLower(strings.TrimSpace(addrs[0])) {
			case "none", "clear", "-":
				addrs = []string{}
			}
		}
		payload := config.Interface{Addresses: addrs}
		return api.patchJSON(ctx, "/api/v1/interfaces/"+args[0], payload, out)
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
		redacted := len(args) > 0 && (args[0] == "redacted" || args[0] == "--redacted")
		var cfg config.Config
		path := "/api/v1/config/export"
		if redacted {
			path += "?redacted=1"
		}
		if err := api.getJSON(ctx, path, &cfg); err != nil {
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
