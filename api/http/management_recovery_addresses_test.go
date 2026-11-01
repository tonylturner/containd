// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// addressEngine records the order of recovery's engine calls and the
// interfaces it configures.
type addressEngine struct {
	*recoveryEngine
	calls      []string
	interfaces [][]config.Interface
	ifaceErr   error
}

func (e *addressEngine) Configure(ctx context.Context, dp config.DataPlaneConfig) error {
	e.calls = append(e.calls, "dataplane")
	return e.recoveryEngine.Configure(ctx, dp)
}

func (e *addressEngine) ApplyRules(ctx context.Context, snap rules.Snapshot) (dpengine.ProtectionStatus, error) {
	e.calls = append(e.calls, "rules")
	return e.recoveryEngine.ApplyRules(ctx, snap)
}

func (e *addressEngine) ConfigureInterfaces(_ context.Context, ifaces []config.Interface) error {
	e.calls = append(e.calls, "interfaces")
	e.interfaces = append(e.interfaces, ifaces)
	return e.ifaceErr
}

// Without a reservation, management can depend on a static address that
// containd itself assigned and that a new container does not have.
// Recovery restores the static addresses of the interfaces it admits
// management on, after the fail-closed ruleset and nothing else of them:
// no zones (forwarding), gateways, virtual devices or DHCP.
func TestManagementRecoveryAppliesManagementAddresses(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	f := false
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{
		{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt", Addresses: []string{"192.0.2.2/24", "2001:db8::2/64"}, Gateway: "192.0.2.1"},
		{Name: "wan0", Device: "wannic", Zone: "wan", Addresses: []string{"198.51.100.2/24"}, Access: config.InterfaceAccess{Mgmt: &f, SSH: &f}},
		{Name: "lan0", Device: "lannic", Zone: "lan", AddressMode: "dhcp"},
		{Name: "lan1", Device: "lan1nic", Zone: "lan"},
		{Name: "vlan10", Device: "mgmtnic.10", Type: "vlan", Parent: "mgmt0", VLANID: 10, Zone: "lan", Addresses: []string{"203.0.113.2/24"}},
	}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.SetManagementBootFault(ctx, "rule modbus-enforce: modbus enforce needs an inline path"); err != nil {
		t.Fatal(err)
	}
	engine := &addressEngine{recoveryEngine: &recoveryEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}}
	warnings, err := ApplyBootConfig(ctx, store, engine, &stageServices{})
	if err != nil || len(warnings) != 0 {
		t.Fatalf("recovery = %v, warnings %q", err, warnings)
	}
	if want := []string{"dataplane", "rules", "interfaces"}; !reflect.DeepEqual(engine.calls, want) {
		t.Fatalf("recovery engine calls %q, want %q", engine.calls, want)
	}
	want := []config.Interface{{Name: "mgmt0", Device: "mgmtnic", Addresses: []string{"192.0.2.2/24", "2001:db8::2/64"}}}
	if !reflect.DeepEqual(engine.interfaces, [][]config.Interface{want}) {
		t.Fatalf("recovery interfaces = %+v, want %+v", engine.interfaces, want)
	}

	// An address failure is a warning: the recovery ruleset is in force.
	engine.calls, engine.interfaces = nil, nil
	engine.ifaceErr = errors.New("interface mgmt0 (mgmtnic) not found")
	warnings, err = ApplyBootConfig(ctx, store, engine, &stageServices{})
	if err != nil || len(warnings) != 1 {
		t.Fatalf("recovery with an address failure = %v, warnings %q", err, warnings)
	}
	if fault, err := store.RuntimeApplyFault(ctx); err != nil || fault != "" {
		t.Fatalf("runtime apply fault = %q, %v", fault, err)
	}
}

// Recovery leaves the addresses of an interface whose stored addresses do
// not all parse, and with a reservation addresses nothing: the reserved
// path does not depend on stored addresses.
func TestRecoveryAddressesOnlyFromValidStoredInterfaces(t *testing.T) {
	stored := config.DefaultConfig()
	stored.Interfaces = []config.Interface{
		{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt", Addresses: []string{"192.0.2.2/24", "not-a-cidr"}},
		{Name: "mgmt1", Device: "mgmt1nic", Zone: "mgmt", Addresses: []string{"192.0.2.3/24"}},
	}
	snap := RecoverySnapshot(stored, nil)
	got := recoveryAddresses(stored, snap.LocalInput)
	if want := []config.Interface{{Name: "mgmt1", Device: "mgmt1nic", Addresses: []string{"192.0.2.3/24"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery addresses = %+v, want %+v", got, want)
	}
	reserved, _ := reservedAPIStore(t)
	if err := reserved.SetManagementBootFault(context.Background(), "stored conflict"); err != nil {
		t.Fatal(err)
	}
	engine := &addressEngine{recoveryEngine: &recoveryEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}}
	if _, err := ApplyBootConfig(context.Background(), reserved, engine, &stageServices{}); err != nil {
		t.Fatal(err)
	}
	if len(engine.interfaces) != 0 {
		t.Fatalf("reserved recovery configured interfaces %+v", engine.interfaces)
	}
}
