package rules

import "testing"

func TestSnapshotDefaults(t *testing.T) {
	s := Snapshot{
		Version: "1",
		Default: ActionAllow,
		Firewall: []Entry{
			{ID: "1", Action: ActionDeny},
		},
	}
	if s.Default != ActionAllow {
		t.Fatalf("expected allow default")
	}
	if len(s.Firewall) != 1 || s.Firewall[0].ID != "1" {
		t.Fatalf("unexpected firewall entries %+v", s.Firewall)
	}
}
