package enforce

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/containd/containd/pkg/dp/rules"
)

// Compiler turns a dp rules.Snapshot into an nftables ruleset.
// This is a minimal Phase 1 skeleton.
type Compiler struct {
	TableName string
}

func NewCompiler() *Compiler {
	return &Compiler{TableName: "containd"}
}

// CompileFirewall builds an nftables ruleset for the snapshot's firewall entries.
// Zone/interface bindings and dynamic sets are added in later phases.
func (c *Compiler) CompileFirewall(snap *rules.Snapshot) (string, error) {
	if snap == nil {
		return "", errors.New("snapshot is nil")
	}
	table := c.TableName
	if table == "" {
		table = "containd"
	}

	var buf bytes.Buffer
	buf.WriteString("flush ruleset\n")
	buf.WriteString(fmt.Sprintf("table inet %s {\n", table))
	buf.WriteString("  set block_hosts {\n")
	buf.WriteString("    type ipv4_addr;\n")
	buf.WriteString("    flags timeout;\n")
	buf.WriteString("  }\n")
	buf.WriteString("  set block_flows {\n")
	buf.WriteString("    type ipv4_addr . ipv4_addr . inet_service;\n")
	buf.WriteString("    flags timeout;\n")
	buf.WriteString("  }\n")
	buf.WriteString("  chain forward {\n")
	buf.WriteString("    type filter hook forward priority 0;\n")
	buf.WriteString(fmt.Sprintf("    policy %s;\n", defaultPolicy(snap.Default)))
	// Dynamic blocks first (verdict-driven).
	buf.WriteString("    ip saddr @block_hosts drop\n")
	buf.WriteString("    ip daddr @block_hosts drop\n")
	buf.WriteString("    meta l4proto { tcp, udp } ip saddr . ip daddr . th dport @block_flows drop\n")

	entries := append([]rules.Entry(nil), snap.Firewall...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		line, err := compileEntry(e)
		if err != nil {
			return "", err
		}
		buf.WriteString("    " + line + "\n")
	}
	buf.WriteString("  }\n")
	buf.WriteString("}\n")
	return buf.String(), nil
}

func defaultPolicy(a rules.Action) string {
	if a == rules.ActionAllow {
		return "accept"
	}
	return "drop"
}

func compileEntry(e rules.Entry) (string, error) {
	parts := []string{}
	parts = append(parts, fmt.Sprintf("comment \"%s\"", e.ID))

	if len(e.Protocols) > 0 {
		// Only first protocol supported in skeleton.
		p := e.Protocols[0]
		if p.Name != "" {
			parts = append(parts, p.Name)
		}
		if p.Port != "" {
			parts = append(parts, fmt.Sprintf("dport %s", p.Port))
		}
	}

	// CIDR matching (skeleton uses ip saddr/daddr; no v6 yet).
	if len(e.Sources) > 0 {
		parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(e.Sources, ", ")))
	}
	if len(e.Destinations) > 0 {
		parts = append(parts, fmt.Sprintf("ip daddr { %s }", strings.Join(e.Destinations, ", ")))
	}

	switch e.Action {
	case rules.ActionAllow:
		parts = append(parts, "accept")
	case rules.ActionDeny:
		parts = append(parts, "drop")
	default:
		return "", fmt.Errorf("unknown action %q in entry %s", e.Action, e.ID)
	}
	return strings.Join(parts, " "), nil
}

// Applier installs an nftables ruleset.
type Applier interface {
	Apply(ctx context.Context, ruleset string) error
}

// NftApplier uses the system `nft` binary.
type NftApplier struct {
	Path string
}

func NewNftApplier() *NftApplier {
	return &NftApplier{Path: "nft"}
}

func (a *NftApplier) Apply(ctx context.Context, ruleset string) error {
	if strings.TrimSpace(ruleset) == "" {
		return errors.New("ruleset is empty")
	}
	path := a.Path
	if path == "" {
		path = "nft"
	}
	cmd := exec.CommandContext(ctx, path, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, string(out))
	}
	return nil
}

// Updater performs verdict-driven dynamic updates against nftables sets/maps.
type Updater interface {
	BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error
	BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error
}

// NftUpdater uses the system `nft` binary to update dynamic sets.
type NftUpdater struct {
	Path      string
	TableName string
}

func NewNftUpdater(table string) *NftUpdater {
	if table == "" {
		table = "containd"
	}
	return &NftUpdater{Path: "nft", TableName: table}
}

func (u *NftUpdater) BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error {
	if ip == nil || ip.To4() == nil {
		return errors.New("invalid IPv4 address")
	}
	args := u.buildBlockHostArgs(ip, ttl)
	return u.run(ctx, args)
}

func (u *NftUpdater) BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error {
	if srcIP == nil || srcIP.To4() == nil || dstIP == nil || dstIP.To4() == nil {
		return errors.New("invalid IPv4 flow endpoints")
	}
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("unsupported proto %q", proto)
	}
	if dport == "" {
		return errors.New("dport required")
	}
	if _, err := strconv.Atoi(dport); err != nil {
		return fmt.Errorf("invalid dport %q", dport)
	}
	args := u.buildBlockFlowArgs(srcIP, dstIP, dport, ttl)
	return u.run(ctx, args)
}

func (u *NftUpdater) buildBlockHostArgs(ip net.IP, ttl time.Duration) []string {
	setName := "block_hosts"
	ipStr := ip.To4().String()
	elem := ipStr
	if ttl > 0 {
		elem = fmt.Sprintf("%s timeout %ds", ipStr, int(ttl.Seconds()))
	}
	return []string{"add", "element", "inet", u.TableName, setName, "{", elem, "}"}
}

func (u *NftUpdater) buildBlockFlowArgs(srcIP, dstIP net.IP, dport string, ttl time.Duration) []string {
	setName := "block_flows"
	key := fmt.Sprintf("%s . %s . %s", srcIP.To4().String(), dstIP.To4().String(), dport)
	elem := key
	if ttl > 0 {
		elem = fmt.Sprintf("%s timeout %ds", key, int(ttl.Seconds()))
	}
	return []string{"add", "element", "inet", u.TableName, setName, "{", elem, "}"}
}

func (u *NftUpdater) run(ctx context.Context, args []string) error {
	path := u.Path
	if path == "" {
		path = "nft"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft update failed: %w: %s", err, string(out))
	}
	return nil
}
