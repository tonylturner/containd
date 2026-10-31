// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func tableEngine(t *testing.T, nft *nftModel, enabled bool, table string) *Engine {
	t.Helper()
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: enabled, TableName: table, Applier: nft, Updater: &recordingUpdater{}}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (m *nftModel) last() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.scripts) == 0 {
		return "", 0
	}
	return m.scripts[len(m.scripts)-1], len(m.scripts)
}

func TestReconfigureWithoutEnforcementDeletesInstalledTables(t *testing.T) {
	nft := &nftModel{}
	e := tableEngine(t, nft, true, "fw")
	// Nothing installed yet: disabling has nothing to delete.
	if err := e.Reconfigure(tableEngine(t, nft, false, "fw")); err != nil {
		t.Fatal(err)
	}
	if _, n := nft.last(); n != 0 {
		t.Fatalf("disable before any apply wrote %d scripts", n)
	}
	if err := e.Reconfigure(tableEngine(t, nft, true, "fw")); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), rules.Snapshot{Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	installed := e.compiler
	if err := e.Reconfigure(tableEngine(t, nft, false, "fw")); err != nil {
		t.Fatal(err)
	}
	if got, n := nft.last(); got != installed.DeleteTables() || n != 2 {
		t.Fatalf("disable wrote script %d %q, want %q", n, got, installed.DeleteTables())
	}
	if e.gate.comp != nil || e.gate.installed {
		t.Fatal("gate still records the deleted ruleset")
	}
	if err := e.Reconfigure(tableEngine(t, nft, false, "fw")); err != nil {
		t.Fatal(err)
	}
	if _, n := nft.last(); n != 2 {
		t.Fatal("a second disable deleted the tables again")
	}
}

func TestReconfigureKeepsEverythingWhenTableDeleteFails(t *testing.T) {
	nft := &nftModel{}
	e := tableEngine(t, nft, true, "")
	if err := e.ApplyRules(context.Background(), rules.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	compiler := e.compiler
	nft.mu.Lock()
	nft.failNext = true
	nft.mu.Unlock()
	if err := e.Reconfigure(tableEngine(t, nft, false, "")); err == nil || !strings.Contains(err.Error(), "remove enforcement tables") {
		t.Fatalf("Reconfigure error = %v", err)
	}
	if e.compiler != compiler || e.gate.comp != compiler {
		t.Fatal("a failed disable changed the engine")
	}
	// The retry deletes them.
	if err := e.Reconfigure(tableEngine(t, nft, false, "")); err != nil {
		t.Fatal(err)
	}
	if got, _ := nft.last(); got != compiler.DeleteTables() {
		t.Fatalf("retry wrote %q", got)
	}
}

func TestRenamedTableRetiresTheInstalledOnesInTheSameApply(t *testing.T) {
	nft := &nftModel{}
	e := tableEngine(t, nft, true, "old")
	snap := rules.Snapshot{Default: rules.ActionDeny}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	old := e.compiler
	// The rename itself leaves the installed tables enforcing until the
	// next apply replaces them.
	if err := e.Reconfigure(tableEngine(t, nft, true, "new")); err != nil {
		t.Fatal(err)
	}
	if _, n := nft.last(); n != 1 {
		t.Fatal("Reconfigure wrote nft while enforcement stays on")
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	compiled, err := e.compiler.CompileFirewall(&snap)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := nft.last(); got != old.DeleteTables()+compiled {
		t.Fatalf("rename apply = %q", got)
	}
	if st := e.RulesetStatus(); st.Ruleset != compiled {
		t.Fatalf("status records %q, want the policy ruleset", st.Ruleset)
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if got, _ := nft.last(); got != compiled {
		t.Fatalf("second apply after the rename = %q", got)
	}
}

func TestClearBlocksFlushesOnlyWhileEnforcing(t *testing.T) {
	nft := &nftModel{}
	e := tableEngine(t, nft, true, "fw")
	if err := e.ClearBlocks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := nft.last(); got != e.compiler.ClearBlocks() || !strings.Contains(got, "flush set inet fw block_hosts") {
		t.Fatalf("clear = %q", got)
	}
	off := tableEngine(t, nft, false, "fw")
	if err := off.ClearBlocks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, n := nft.last(); n != 1 {
		t.Fatal("clearing blocks without enforcement wrote nft")
	}
}

func TestApplyConvergesTheLiveDynamicTable(t *testing.T) {
	nft := &nftModel{live: enforce.TableLayout{Exists: true, Chains: []enforce.LiveChain{
		{Name: "input", Type: "filter", Hook: "input", Policy: "drop"},
	}}}
	e := tableEngine(t, nft, true, "")
	snap := rules.Snapshot{Default: rules.ActionDeny}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	compiled, err := e.compiler.CompileFirewall(&snap)
	if err != nil {
		t.Fatal(err)
	}
	want := "flush chain inet containd input\ndelete chain inet containd input\n" + compiled
	if got, _ := nft.last(); got != want {
		t.Fatalf("apply = %q, want %q", got, want)
	}
	if st := e.RulesetStatus(); st.Ruleset != compiled {
		t.Fatalf("status records %q, want the compiled ruleset", st.Ruleset)
	}
}

func TestApplyFailsWhenTheDynamicTableCannotBeRead(t *testing.T) {
	nft := &nftModel{readErr: errors.New("nft: permission denied")}
	e := tableEngine(t, nft, true, "")
	err := e.ApplyRules(context.Background(), rules.Snapshot{})
	if err == nil || !strings.Contains(err.Error(), "read nft table containd") {
		t.Fatalf("ApplyRules error = %v", err)
	}
	if _, n := nft.last(); n != 0 || e.CurrentRules() != nil || e.RulesetStatus().Error == "" {
		t.Fatal("an unread table was written or the snapshot swapped")
	}
}
