// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

type markClear struct{ mask, value, clear uint32 }

func admissionEngine(t *testing.T) (*Engine, *recordingApplier) {
	t.Helper()
	nft := &recordingApplier{}
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, Applier: nft, ClearMark: noPolicyMarks}})
	if err != nil {
		t.Fatal(err)
	}
	e.localIPv4 = func(*rules.Snapshot) (map[string][]netip.Addr, error) { return nil, nil }
	return e, nft
}

func TestAdmissionParityNoopFlipAndRecovery(t *testing.T) {
	e, nft := admissionEngine(t)
	var calls []markClear
	fail := false
	e.clearMarks = func(_ context.Context, mask, value, clear uint32) (int, error) {
		calls = append(calls, markClear{mask, value, clear})
		if fail {
			return 0, errors.New("interrupted dump")
		}
		return 3, nil
	}
	ctx := context.Background()
	snap := rules.Snapshot{Version: "first", Default: rules.ActionAllow}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []markClear{
		{markabi.AdmittedBit, markabi.AdmittedBit, markabi.AdmittedBit},
		{enforce.GateCtMark, enforce.GateCtMark, enforce.GateZoneCtMask},
	}) || e.CurrentRules().AdmissionParity != 0 {
		t.Fatalf("startup: calls=%v policy=%+v", calls, e.admission)
	}
	calls = nil
	e.verdictCache.Put("stale", verdict.Verdict{Action: verdict.DenyDrop})
	snap.Version = "same"
	e.SetICSParsing(map[string]string{"modbus": "tolerant"})
	if err := e.ApplyRules(ctx, snap); err != nil || len(calls) != 0 || e.verdictCache.Len() != 0 {
		t.Fatalf("no-op: err=%v calls=%v cache=%d", err, calls, e.verdictCache.Len())
	}
	nft.err = errors.New("atomic install failed")
	snap.Default = rules.ActionDeny
	if err := e.ApplyRules(ctx, snap); err == nil || e.CurrentRules().AdmissionParity != 0 || len(calls) != 0 {
		t.Fatalf("failed install changed publication/parity: %v, %v", err, calls)
	}
	nft.err = nil
	fail = true
	snap.Version = "installed-sweep-failed"
	if err := e.ApplyRules(ctx, snap); err == nil || !e.admission.dirty || e.IEC104Enforcement().Healthy {
		t.Fatalf("sweep failure: err=%v health=%+v", err, e.IEC104Enforcement())
	}
	if e.CurrentRules().AdmissionParity != markabi.ParityBit || e.RulesetStatus().SnapshotVersion != snap.Version ||
		!reflect.DeepEqual(calls, []markClear{{markabi.AdmissionCtMask, markabi.AdmittedBit, markabi.AdmittedBit}}) {
		t.Fatalf("sweep/publication=%v %+v", calls, e.admission)
	}
	calls = nil
	snap.Default = rules.ActionAllow
	if err := e.ApplyRules(ctx, snap); err == nil || e.CurrentRules().Default != rules.ActionDeny {
		t.Fatal("reused parity without successful recovery")
	}
	fail, calls = false, nil
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []markClear{
		{markabi.AdmittedBit, markabi.AdmittedBit, markabi.AdmittedBit},
		{markabi.AdmissionCtMask, markabi.AdmittedBit | markabi.ParityBit, markabi.AdmittedBit},
	}) || e.CurrentRules().AdmissionParity != 0 || !e.IEC104Enforcement().Healthy {
		t.Fatalf("recovery=%v policy=%+v health=%+v", calls, e.admission, e.IEC104Enforcement())
	}
}

func TestPreviewUsesChosenParityAndResolverInputs(t *testing.T) {
	e, _ := admissionEngine(t)
	e.localIPv4 = func(*rules.Snapshot) (map[string][]netip.Addr, error) {
		return map[string][]netip.Addr{"wan0": {netip.MustParseAddr("203.0.113.2")}}, nil
	}
	snap := rules.Snapshot{Default: rules.ActionAllow}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	snap.Default = rules.ActionDeny
	preview, err := e.PreviewRuleset(snap, enforce.CompilerSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Snapshot.AdmissionParity != markabi.ParityBit || len(preview.Snapshot.LocalIPv4ByDevice["wan0"]) != 1 ||
		e.CurrentRules().AdmissionParity != 0 {
		t.Fatalf("preview did not isolate runtime inputs: %+v", preview.Snapshot)
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if preview.Ruleset != e.RulesetStatus().Ruleset {
		t.Fatal("parity preview differs from installed policy")
	}
}

func TestGateIndexRetirementAndFailedReuse(t *testing.T) {
	e, _ := admissionEngine(t)
	ctx := context.Background()
	snap := rules.Snapshot{Gate: rules.GateSelection{Zones: []rules.GateZone{{Name: "old", Index: 1}}}}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	var calls []markClear
	fail := true
	e.clearMarks = func(_ context.Context, mask, value, clear uint32) (int, error) {
		calls = append(calls, markClear{mask, value, clear})
		if fail && clear == enforce.GateZoneCtMask {
			return 0, errors.New("zone sweep failed")
		}
		return 1, nil
	}
	snap.Gate.Zones = []rules.GateZone{{Name: "new", Index: 1}}
	if err := e.ApplyRules(ctx, snap); err == nil || !e.admission.gateDirty || e.CurrentRules().Gate.Zones[0].Index != 2 {
		t.Fatalf("retirement/reallocation: err=%v calls=%v current=%+v", err, calls, e.CurrentRules().Gate)
	}
	want := markClear{enforce.GateCtMark | enforce.GateZoneCtMask, enforce.GateCtMark | 1<<enforce.GateZoneCtShift, enforce.GateZoneCtMask}
	if calls[len(calls)-1] != want {
		t.Fatalf("retirement mask = %+v, want %+v", calls, want)
	}
	snap.Gate.Zones = append(snap.Gate.Zones, rules.GateZone{Name: "reuse", Index: 3})
	if err := e.ApplyRules(ctx, snap); err == nil || len(e.CurrentRules().Gate.Zones) != 1 {
		t.Fatal("reused a retired index before recovery")
	}
	fail, calls = false, nil
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	if e.CurrentRules().Gate.Zones[1].Index != 1 || e.admission.gateDirty || !e.IEC104Enforcement().Healthy {
		t.Fatalf("recovery did not free retired index: %+v", e.CurrentRules().Gate)
	}
	// Recovery clears every non-live index before the next installation.
	if len(calls) != 255 || calls[0] != want {
		t.Fatalf("full retired-allocation recovery=%v", calls)
	}
}

type publicationApplier struct {
	*recordingApplier
	e *Engine
}

func (a publicationApplier) Apply(ctx context.Context, script string) error {
	if a.e.policyMu.TryRLock() {
		a.e.policyMu.RUnlock()
		return errors.New("nft install outside publication write lock")
	}
	if a.e.CurrentRules() != nil {
		return errors.New("snapshot published before nft installation")
	}
	return a.recordingApplier.Apply(ctx, script)
}

func TestApplyPublicationPrecedesInstallAndSerializesSweeps(t *testing.T) {
	e, nft := admissionEngine(t)
	e.applier = publicationApplier{nft, e}
	if err := e.ApplyRules(context.Background(), rules.Snapshot{Default: rules.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	e.applier = nft
	sweeping, release := make(chan struct{}), make(chan struct{})
	e.clearMarks = func(context.Context, uint32, uint32, uint32) (int, error) {
		close(sweeping)
		<-release
		return 1, nil
	}
	first := make(chan error, 1)
	go func() { first <- e.ApplyRules(context.Background(), rules.Snapshot{Default: rules.ActionDeny}) }()
	select {
	case <-sweeping:
	case <-time.After(3 * time.Second):
		t.Fatal("apply did not reach sweep")
	}
	if !e.policyMu.TryRLock() {
		t.Error("sweep blocks policy readers")
	} else {
		e.policyMu.RUnlock()
	}
	if e.lifecycleMu.TryLock() {
		e.lifecycleMu.Unlock()
		t.Error("another flip can start during sweep")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.RulesetStatus().Ruleset, "0x00000006") {
		t.Fatal("installed policy did not use chosen parity")
	}
}

func TestPacketVerdictDuringAdmissionSweep(t *testing.T) {
	for _, tc := range []struct {
		name string
		mask uint32
	}{
		{"parity", markabi.AdmittedBit},
		{"retired gate index", enforce.GateZoneCtMask},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := admissionEngine(t)
			ctx := context.Background()
			snap := rules.Snapshot{Default: rules.ActionAllow,
				Gate: rules.GateSelection{Zones: []rules.GateZone{{Name: "old", Index: 1}}}}
			if err := e.ApplyRules(ctx, snap); err != nil {
				t.Fatal(err)
			}
			sweeping, release, applied := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			e.clearMarks = func(_ context.Context, _, _, clear uint32) (int, error) {
				if clear == tc.mask {
					close(sweeping)
					<-release
				}
				return 1, nil
			}
			// Retiring the zone changes policy and exercises both sweep
			// classes; each subtest stalls only its selected class.
			snap.Gate.Zones = nil
			snap.Version = "new-policy"
			var applyErr error
			var packetDone chan struct{}
			t.Cleanup(func() {
				unblock()
				<-applied
				if packetDone != nil {
					<-packetDone
				}
			})
			go func() {
				defer close(applied)
				applyErr = e.ApplyRules(ctx, snap)
			}()
			select {
			case <-sweeping:
			case <-time.After(3 * time.Second):
				t.Fatal("apply did not reach sweep")
			}
			if e.lifecycleMu.TryLock() {
				e.lifecycleMu.Unlock()
				t.Fatal("sweep did not exclude another flip/index reuse")
			}
			verdict := make(chan capture.Decision, 1)
			packetDone = make(chan struct{})
			go func() {
				defer close(packetDone)
				verdict <- e.HandlePacket(modbusWritePacket(capture.NewToken(1, 1)))
			}()
			select {
			case d := <-verdict:
				if d.Action != capture.Repeat || d.Mark&markabi.ObservedMark == 0 {
					t.Fatalf("packet verdict=%+v", d)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("packet verdict blocked behind sweep")
			}
			select {
			case <-applied:
				t.Fatal("apply completed before sweep was released")
			default:
			}
			if e.CurrentRules().Version != snap.Version || e.CurrentRules().AdmissionParity != markabi.ParityBit {
				t.Fatal("packet did not have the new published policy")
			}
			unblock()
			<-applied
			if applyErr != nil {
				t.Fatal(applyErr)
			}
		})
	}
}

func TestAdmissionStartupClearBeforeBinding(t *testing.T) {
	e, _ := admissionEngine(t)
	capture := &bindCapture{}
	e.capture = capture
	fail := true
	e.clearMarks = func(context.Context, uint32, uint32, uint32) (int, error) {
		if fail {
			return 0, errors.New("startup clear failed")
		}
		return 0, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := e.Start(ctx); err == nil || e.started.Load() || e.IEC104Enforcement().Healthy {
		t.Fatalf("startup activated without recovery: %v", err)
	}
	fail = false
	if err := e.Start(ctx); err != nil || !e.started.Load() || !e.IEC104Enforcement().Healthy {
		t.Fatalf("startup recovery=%v health=%+v", err, e.IEC104Enforcement())
	}
	done := e.runDone
	cancel()
	<-done
}
