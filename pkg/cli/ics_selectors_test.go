// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestICSSelectorFlags(t *testing.T) {
	no := false
	for _, tc := range []struct {
		protocol string
		flags    string
		want     config.ICSPredicate
	}{
		{"dnp3", "--masters 0,65519 --outstations 1 --groups 0,50,80 --variations 0,255 --addresses 0-4294967295 --function-code 0",
			config.ICSPredicate{Protocol: "dnp3", Masters: []uint16{0, 65519}, Outstations: []uint16{1}, Groups: []int{0, 50, 80}, Variations: []int{0, 255}, Addresses: []string{"0-4294967295"}, FunctionCode: []uint8{0}}},
		{"cip", "--instances 0,0xFFFF --attributes 0,65535",
			config.ICSPredicate{Protocol: "cip", Instances: []uint16{0, 65535}, Attributes: []uint16{0, 65535}}},
		{"cip", "--tags Motor.Speed,Program:Main.Pump",
			config.ICSPredicate{Protocol: "cip", Tags: []string{"Motor.Speed", "Program:Main.Pump"}}},
		{"iec104", "--type-ids 46 --command-states 1,2 --command-qualifiers 0,31",
			config.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, CommandStates: []int{1, 2}, CommandQualifiers: []int{0, 31}}},
		{"iec104", "--cot 1,63 --originators 0,255 --negative false --test false --select-execute execute",
			config.ICSPredicate{Protocol: "iec104", COT: []int{1, 63}, Originators: []int{0, 255}, Negative: &no, Test: &no, SelectExecute: "execute"}},
	} {
		t.Run(tc.flags, func(t *testing.T) {
			args := append([]string{"rule", "ALLOW", tc.protocol}, strings.Fields(tc.flags)...)
			got, err := parseFirewallICSRuleArgs(args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.ICS, tc.want) {
				t.Fatalf("got %+v, want %+v", got.ICS, tc.want)
			}
		})
	}
}

func TestICSSelectorFlagBounds(t *testing.T) {
	for _, flags := range []string{
		"--masters 65520", "--outstations 65535", "--groups 256", "--variations -1",
		"--instances 65536", "--attributes 1.5", "--cot 0", "--cot 64",
		"--originators 256", "--negative 0", "--test yes", "--select-execute other",
		"--command-states 3", "--command-states -1", "--command-qualifiers 32", "--command-qualifiers 1.5", "--tags ,", "--groups 1,", "--instances",
	} {
		if _, err := parseFirewallICSRuleArgs(append([]string{"rule", "ALLOW", "dnp3"}, strings.Fields(flags)...)); err == nil {
			t.Errorf("accepted invalid %s", flags)
		}
	}
}

func TestICSSelectorShowTable(t *testing.T) {
	no, yes := false, true
	var out bytes.Buffer
	renderFirewallICSRules(&out, []config.Rule{
		{ID: "dnp", ICS: config.ICSPredicate{Protocol: "dnp3", Masters: []uint16{0, 65519}, Outstations: []uint16{2, 3}, Groups: []int{50, 80}, Variations: []int{0, 1}}},
		{ID: "cip-logical", ICS: config.ICSPredicate{Protocol: "cip", Instances: []uint16{0, 65535}, Attributes: []uint16{3, 4}}},
		{ID: "cip-tag", ICS: config.ICSPredicate{Protocol: "cip", Tags: []string{"Program:Main.Motor"}}},
		{ID: "iec", ICS: config.ICSPredicate{Protocol: "iec104", COT: []int{1, 63}, Originators: []int{0, 255}, Negative: &no, Test: &yes, SelectExecute: "execute", CommandStates: []int{1, 2}, CommandQualifiers: []int{0, 31}}},
	}, "monitor")
	for _, want := range []string{"MASTERS", "OUTSTATIONS", "GROUPS", "VARIATIONS", "INSTANCES", "ATTRIBUTES", "TAGS", "COT", "ORIGINATORS", "NEGATIVE", "TEST", "SELECT_EXECUTE", "COMMAND_STATES", "COMMAND_QUALIFIERS", "1,2", "0,31", "0,65519", "2,3", "50,80", "0,1", "0,65535", "3,4", "Program:Main.Motor", "1,63", "0,255", "false", "true", "execute"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table missing %q: %s", want, out.String())
		}
	}
}
