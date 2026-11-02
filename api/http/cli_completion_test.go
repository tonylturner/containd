// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"slices"
	"strings"
	"testing"

	"github.com/kballard/go-shellquote"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func policyCompletionForLine(t *testing.T, line string, cfg *config.Config) []string {
	t.Helper()
	tokens, err := shellquote.Split(line)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(line, " ") {
		tokens = append(tokens, "")
	}
	commands := cli.NewRegistry(nil, &cli.API{}).CommandsForRole(cli.RoleAdmin)
	command, args := matchCommandTokens(tokens, commands)
	if command == "" {
		t.Fatalf("no command matched %q", line)
	}
	return completeCLIArgs(command, args, cfg, commands)
}

func TestCLICompletionFirewallEdits(t *testing.T) {
	cfg := &config.Config{Firewall: config.FirewallConfig{Rules: []config.Rule{{ID: "plant-safe"}, {ID: "plant"}, {ID: "ops"}}}, Zones: []config.Zone{{Name: "lan"}, {Name: "plant"}}}
	cfg.Firewall.NAT.PortForwards = []config.PortForward{{ID: "publish"}}
	common := strings.Fields("--action --description --tag --src-zone --source-zones --dst-zone --dest-zones --sources --destinations --protocols --identities --via-forwards --log --rate-limit --schedule --schedule-days --schedule-start --schedule-end --schedule-timezone")
	ics := strings.Fields("--ics-protocol --function-code --object-classes --unit-id --addresses --read-only --write-only --mode --type-ids --classes --ca --ioa --direction --masters --outstations --groups --variations --instances --attributes --tags --cot --originators --negative --test --select-execute --command-states --command-qualifiers")
	for _, command := range []string{"set firewall rule", "set firewall ics-rule"} {
		t.Run(command, func(t *testing.T) {
			flags := slices.Clone(common)
			if strings.HasSuffix(command, "ics-rule") {
				flags = append(flags, ics...)
			}
			slices.Sort(flags)
			for _, suffix := range []string{"plant ", "plant --log true ", "plant --description '' "} {
				got := policyCompletionForLine(t, command+" "+suffix, cfg)
				if !slices.Equal(got, flags) {
					t.Fatalf("%q: got %v want %v", suffix, got, flags)
				}
			}
			for _, tc := range []struct {
				suffix string
				want   []string
			}{
				{" ", []string{"ops", "plant", "plant-safe"}},
				{" pl", []string{"plant", "plant-safe"}},
				{" plant --act", []string{"--action"}},
				{" plant --action ", []string{"ALLOW", "DENY", "RATE_LIMIT", "RESET", "TAG"}},
				{" plant --log ", []string{"false", "true"}},
				{" plant --source-zones ", []string{"lan", "plant"}},
				{" plant --dest-zones pl", []string{"plant"}},
				{" plant --via-forwards ", []string{"publish"}},
				{" plant --description ", []string{"<text>"}},
				{" plant --rate-limit ", []string{"<pps[:burst]>", "none"}},
				{" plant --schedule ", []string{"none"}},
				{" plant --unknown ", nil},
				{" plant A", nil},
			} {
				got := policyCompletionForLine(t, command+tc.suffix, cfg)
				if !slices.Equal(got, tc.want) {
					t.Fatalf("%q: got %v want %v", tc.suffix, got, tc.want)
				}
			}
		})
	}
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"set firewall ics-rule plant --ics-protocol ", []string{"cip", "dnp3", "iec104", "modbus"}},
		{"set firewall ics-rule plant --read-only ", []string{"false", "true"}},
		{"set firewall ics-rule plant --read-only false --mode ", []string{"enforce", "monitor"}},
		{"set firewall rule plant --ics", nil},
		{"set firewall rule plant --ics-protocol ", nil},
	} {
		if got := policyCompletionForLine(t, tc.line, cfg); !slices.Equal(got, tc.want) {
			t.Fatalf("%q: got %v want %v", tc.line, got, tc.want)
		}
	}
	if got := policyCompletionForLine(t, "set firewall rule ", nil); len(got) != 0 {
		t.Fatalf("invented existing rules: %v", got)
	}
}

func TestCLICompletionFirewallCreates(t *testing.T) {
	cfg := &config.Config{Firewall: config.FirewallConfig{Rules: []config.Rule{{ID: "anchor"}}}, Zones: []config.Zone{{Name: "plant"}}}
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"add firewall rule ", []string{"<id>"}},
		{"add firewall rule new ", []string{"ALLOW", "DENY", "allow", "deny"}},
		{"add firewall rule new ALLOW ", []string{"after", "before", "bottom", "plant", "top"}},
		{"add firewall rule new ALLOW plant plant ", []string{"after", "before", "bottom", "top"}},
		{"add firewall rule new ALLOW plant plant before ", []string{"anchor"}},
		{"add firewall ics-rule ", []string{"<id>"}},
		{"add firewall ics-rule new ", []string{"ALLOW", "DENY"}},
		{"add firewall ics-rule new ALLOW ", []string{"cip", "dnp3", "iec104", "modbus"}},
		{"add firewall ics-rule new ALLOW modbus --src-zone ", []string{"plant"}},
		{"add firewall ics-rule new ALLOW modbus --mode ", []string{"enforce", "monitor"}},
		{"add firewall ics-rule new ALLOW modbus --function-code ", []string{"<codes_csv>"}},
		{"add firewall ics-rule new ALLOW modbus --read-only --mo", []string{"--mode"}},
		{"add firewall ics-rule new ALLOW modbus --action ", nil},
		{"add firewall ics-rule new ALLOW modbus --ics-protocol ", nil},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := policyCompletionForLine(t, tc.line, cfg); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	flags := policyCompletionForLine(t, "add firewall ics-rule new ALLOW modbus ", cfg)
	afterBare := policyCompletionForLine(t, "add firewall ics-rule new ALLOW modbus --read-only ", cfg)
	if !slices.Equal(flags, afterBare) || !slices.Contains(flags, "--read-only") || !slices.Contains(flags, "--function-code") {
		t.Fatalf("creation switches: %v / %v", flags, afterBare)
	}
	for _, unsupported := range []string{"--ics-protocol", "--action", "--source-zones", "ALLOW", "before"} {
		if slices.Contains(flags, unsupported) {
			t.Fatalf("invalid create option %s", unsupported)
		}
	}
}

func TestCLICompletionFirewallUsageHints(t *testing.T) {
	for _, command := range []string{"set firewall rule", "set firewall ics-rule"} {
		if got := usageHints(command, 0, []string{""}); !slices.Equal(got, []string{"<id>"}) {
			t.Fatalf("%s ID hints: %v", command, got)
		}
		for _, args := range [][]string{{"id", ""}, {"id", "--log", "false", ""}} {
			got := usageHints(command, len(args)-1, args)
			if len(got) == 0 {
				t.Fatalf("%s no edit hints", command)
			}
			for _, hint := range got {
				if !strings.HasPrefix(hint, "--") {
					t.Fatalf("%s positional edit hint %q", command, hint)
				}
			}
		}
		if got := usageHints(command, 2, []string{"id", "--log", ""}); !slices.Equal(got, []string{"true", "false"}) {
			t.Fatalf("%s bool hints: %v", command, got)
		}
	}
	for _, command := range []string{"add firewall rule", "add firewall ics-rule"} {
		if got := usageHints(command, 1, []string{"id", ""}); !slices.Equal(got, []string{"ALLOW", "DENY"}) {
			t.Fatalf("%s create hints: %v", command, got)
		}
	}
	if got := usageHints("add firewall ics-rule", 4, []string{"id", "ALLOW", "modbus", "--mode", ""}); !slices.Equal(got, []string{"monitor", "enforce"}) {
		t.Fatalf("ICS create mode hints: %v", got)
	}
}
