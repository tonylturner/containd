package rules

import (
	"net"
	"testing"
)

func TestEvaluatorMatch(t *testing.T) {
	snap := Snapshot{
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:           "1",
				SourceZones:  []string{"it"},
				DestZones:    []string{"dmz"},
				Sources:      []string{"192.168.1.0/24"},
				Destinations: []string{"10.0.0.0/24"},
				Protocols:    []Protocol{{Name: "tcp", Port: "80"}},
				Action:       ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		SrcZone: "it",
		DstZone: "dmz",
		SrcIP:   net.ParseIP("192.168.1.10"),
		DstIP:   net.ParseIP("10.0.0.5"),
		Proto:   "tcp",
		Port:    "80",
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
}

func TestEvaluatorDefaultDeny(t *testing.T) {
	ev := NewEvaluator(&Snapshot{Default: ActionDeny})
	ctx := EvalContext{}
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}

func TestPortRange(t *testing.T) {
	snap := Snapshot{
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:        "1",
				Protocols: []Protocol{{Name: "tcp", Port: "1000-2000"}},
				Action:    ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{Proto: "tcp", Port: "1500"}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
	ctx.Port = "80"
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}

func TestIdentityMatch(t *testing.T) {
	snap := Snapshot{
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:         "1",
				Identities: []string{"operator"},
				Action:     ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{Identities: []string{"operator"}}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
	ctx.Identities = []string{"guest"}
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}

func TestICSMatch(t *testing.T) {
	unit := uint8(1)
	snap := Snapshot{
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID: "1",
				ICS: ICSPredicate{
					Protocol:     "modbus",
					FunctionCode: []uint8{3, 16},
					UnitID:       &unit,
				},
				Action: ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		ICS: &ICSContext{
			Protocol:     "modbus",
			FunctionCode: 3,
			UnitID:       &unit,
		},
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
	ctx.ICS.FunctionCode = 5
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}
