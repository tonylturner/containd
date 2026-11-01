// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestShadowWarnings(t *testing.T) {
	tcp := func(port string) []rules.Protocol { return []rules.Protocol{{Name: "tcp", Port: port}} }
	snap := &rules.Snapshot{Firewall: []rules.Entry{
		{ID: "allow-ot-web", SourceZones: []string{"it", "dmz"}, Destinations: []string{"10.0.0.0/16"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "80-443"}}, Action: rules.ActionAllow},
		{ID: "allow-modbus", Protocols: tcp("502"), ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"}, Action: rules.ActionAllow},
		{ID: "allow-guest", Protocols: tcp("22"), Identities: []string{"guest"}, Action: rules.ActionAllow},
		{ID: "allow-dnp3-read", Protocols: tcp("20000"), ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "dnp3", FunctionCode: []uint8{1}}, Action: rules.ActionAllow},
		// Shadowed:
		{ID: "deny-http", SourceZones: []string{"it"}, Destinations: []string{"10.0.5.7/32"}, Protocols: tcp("80"), Action: rules.ActionDeny},
		{ID: "reset-https", SourceZones: []string{"dmz"}, Destinations: []string{"10.0.1.0/24"}, Protocols: tcp("443"), Action: rules.ActionReset},
		{ID: "deny-modbus-write", Protocols: tcp("502"), ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus", FunctionCode: []uint8{6}}, Action: rules.ActionDeny},
		// Not shadowed:
		{ID: "deny-any-zone", Destinations: []string{"10.0.5.7/32"}, Protocols: tcp("80"), Action: rules.ActionDeny},
		{ID: "deny-wider-net", SourceZones: []string{"it"}, Destinations: []string{"10.0.0.0/8"}, Protocols: tcp("80"), Action: rules.ActionDeny},
		{ID: "deny-wider-ports", SourceZones: []string{"it"}, Destinations: []string{"10.0.5.7/32"}, Protocols: tcp("1-1024"), Action: rules.ActionDeny},
		{ID: "deny-udp", SourceZones: []string{"it"}, Destinations: []string{"10.0.5.7/32"}, Protocols: []rules.Protocol{{Name: "udp", Port: "80"}}, Action: rules.ActionDeny},
		{ID: "deny-ssh", Protocols: tcp("22"), Action: rules.ActionDeny},
		{ID: "deny-dnp3-write", Protocols: tcp("20000"), ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "dnp3", FunctionCode: []uint8{2}}, Action: rules.ActionDeny},
		{ID: "deny-plain-502", Protocols: tcp("502"), Action: rules.ActionDeny},
		{ID: "deny-iec", Protocols: tcp("2404"), ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "iec104"}, Action: rules.ActionDeny},
		{ID: "police-http", SourceZones: []string{"it"}, Destinations: []string{"10.0.5.7/32"}, Protocols: tcp("80"), Action: rules.ActionRateLimit,
			RateLimit: &rules.RateLimit{PacketsPerSecond: 1}},
	}}
	var got [][2]string
	for _, w := range NewCompiler().RuleWarnings(snap) {
		if w.ShadowedBy != "" {
			got = append(got, [2]string{w.RuleID, w.ShadowedBy})
		}
	}
	want := [][2]string{{"deny-http", "allow-ot-web"}, {"deny-modbus-write", "allow-modbus"}, {"reset-https", "allow-ot-web"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shadowed = %v, want %v", got, want)
	}
}

func TestShadowUsesOnlyEarlierTerminals(t *testing.T) {
	for _, first := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
		for _, second := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
			snap := &rules.Snapshot{Firewall: []rules.Entry{
				{ID: "z-first", Action: first}, {ID: "a-second", Action: second},
			}}
			w := shadowWarnings(snap)
			if len(w) != 1 || w[0].RuleID != "a-second" || w[0].ShadowedBy != "z-first" ||
				!strings.Contains(w[0].Message, "position 2") || !strings.Contains(w[0].Message, "position 1") {
				t.Fatalf("%s/%s: %v", first, second, w)
			}
			snap.Firewall[0].Action = rules.ActionTag
			if w := shadowWarnings(snap); len(w) != 0 {
				t.Fatalf("effect shadows terminal: %v", w)
			}
			snap.Firewall[0].Action = first
			snap.Firewall[0].ViaForwards = []string{"f"}
			if w := shadowWarnings(snap); len(w) != 0 {
				t.Fatalf("via-only rule covers direct traffic: %v", w)
			}
		}
	}
}

// Every semantic selector, including selectors added later, must prevent
// treating an application-scoped terminal as unconditional coverage.
func TestICSEmptyIncludesEverySelector(t *testing.T) {
	typ := reflect.TypeFor[rules.ICSPredicate]()
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			var pred rules.ICSPredicate
			field := reflect.ValueOf(&pred).Elem().Field(i)
			switch field.Kind() {
			case reflect.String:
				field.SetString("x")
			case reflect.Bool:
				field.SetBool(true)
			case reflect.Pointer:
				field.Set(reflect.New(field.Type().Elem()))
			case reflect.Slice:
				field.Set(reflect.MakeSlice(field.Type(), 1, 1))
			default:
				t.Fatalf("new selector kind %s needs coverage", field.Kind())
			}
			if icsEmpty(pred) {
				t.Fatalf("%s omitted from emptiness", name)
			}
			if name != "Protocol" && name != "Mode" && unconditional(rules.Entry{ICS: pred}) {
				t.Fatalf("%s omitted from unconditional coverage", name)
			}
		})
	}
}

// A broad L4 ALLOW does not shadow an IEC104 DENY: IEC104 objects are
// decided among IEC104 rules alone.
func TestShadowWarningsLeaveIEC104Out(t *testing.T) {
	snap := iecSnapshot()
	snap.Firewall = append([]rules.Entry{{ID: "any", Action: rules.ActionAllow}}, snap.Firewall...)
	for _, w := range NewCompiler().RuleWarnings(snap) {
		if w.ShadowedBy != "" && isIEC104Rule(entryByID(snap, w.RuleID)) {
			t.Fatalf("IEC104 rule reported shadowed: %+v", w)
		}
	}
}

func entryByID(snap *rules.Snapshot, id string) rules.Entry {
	for _, e := range snap.Firewall {
		if e.ID == id {
			return e
		}
	}
	return rules.Entry{}
}
