// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"go.uber.org/zap"
)

func protocolPost(h http.Handler, m protection.Metadata, previous string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	setProtectionHeaders(r, string(m.ApplyID), previous, string(m.RunningRevision))
	r.Header.Set(protection.EngineBootIDHeader, string(m.BootID))
	r.Header.Set(protection.ApplyModeHeader, string(m.Mode))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func protocolMetadata(id string) protection.Metadata {
	return protection.Metadata{BootID: protection.BootID(engineBootID), ApplyID: protection.ApplyID(id),
		RunningRevision: "running", Mode: protection.ModeNormal}
}

func TestProtectionAdmissionEveryPhaseHeaders(t *testing.T) {
	for _, phase := range []string{"config", "nft", "interfaces", "routing", "trust", "services"} {
		t.Run(phase, func(t *testing.T) {
			dp := newCountingDP(t)
			c := testProtectionCoordinator(t, dp)
			calls := 0
			h := c.admit(phase, func(http.ResponseWriter, *http.Request) { calls++ })
			for _, header := range []string{protection.ApplyIDHeader, protection.EngineBootIDHeader,
				protection.RunningRevisionHeader, protection.ApplyModeHeader, protection.PreviousApplyIDHeader} {
				r := protectionRequest(http.MethodPost, "/", strings.NewReader(`{}`))
				r.Header.Del(header)
				w := httptest.NewRecorder()
				h(w, r)
				if w.Code < 400 || calls != 0 || c.current != "" {
					t.Fatalf("missing %s admitted: %d %s", header, w.Code, w.Body)
				}
			}
			if w := protocolPost(h, protocolMetadata("first"), "", `{}`); w.Code != 200 || calls != 1 {
				t.Fatalf("complete identity refused: %d %s", w.Code, w.Body)
			}
			// Predecessor is required only for first admission, not each phase.
			r := protectionRequest(http.MethodPost, "/", strings.NewReader(`{}`))
			setProtectionHeaders(r, "first", "", "running")
			r.Header.Del(protection.PreviousApplyIDHeader)
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != 200 || calls != 2 {
				t.Fatalf("current identity refused: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestProtectionAdmissionImmutableTargetAndPredecessor(t *testing.T) {
	dp := newCountingDP(t)
	c := testProtectionCoordinator(t, dp)
	now := time.Now()
	c.now = func() time.Time { return now }
	calls := 0
	h := c.admit("config", func(http.ResponseWriter, *http.Request) { calls++ })
	post := func(m protection.Metadata, previous, body string, want int) {
		t.Helper()
		if w := protocolPost(h, m, previous, body); w.Code != want {
			t.Fatalf("%+v previous=%s: %d %s", m, previous, w.Code, w.Body)
		}
	}
	first := protocolMetadata("z-first")
	post(first, "", `{"a":1,"b":2}`, 200)
	post(first, "", `{ "b":2, "a":1 }`, 200)
	changed := first
	changed.BootID += "-other"
	post(changed, "", `{}`, 409)
	changed = first
	changed.RunningRevision += "-other"
	post(changed, "", `{}`, 409)
	changed = first
	changed.Mode, changed.RunningRevision = protection.ModeRecovery, protection.RecoveryRevision(first.BootID)
	post(changed, "", `{"enforcement":true}`, 409)
	post(first, "", `{"a":2}`, 409)
	next := protocolMetadata("a-next")
	post(next, "", `{}`, 409)
	now = now.Add(-24 * time.Hour) // never order identity by the wall clock
	post(next, string(first.ApplyID), `{}`, 200)
	post(first, string(next.ApplyID), `{"a":1,"b":2}`, 409)
	// Even an unseen request delayed beyond seen retention cannot replace a
	// newer target with an outdated predecessor.
	now = now.Add(48 * time.Hour)
	post(protocolMetadata("unseen"), string(first.ApplyID), `{}`, 409)
	post(first, "", `{"a":1,"b":2}`, 409)
	post(next, "", `{}`, 200)
	if calls != 4 || c.current != string(next.ApplyID) {
		t.Fatalf("rejected request had effects: calls=%d current=%s", calls, c.current)
	}
}

func subsystem(t *testing.T, st engine.ProtectionStatus, name protection.SubsystemName) protection.OwnerOutcome {
	t.Helper()
	for _, o := range st.Subsystems {
		if o.Name == name {
			return o
		}
	}
	t.Fatalf("missing %s: %+v", name, st)
	return protection.OwnerOutcome{}
}

func TestProtectionPartialInterfaceMutationInvalidatesOnlyOwner(t *testing.T) {
	dp := protocolEngine(t)
	c := testProtectionCoordinator(t, dp)
	m := protocolMetadata("interface-attempt")
	apply := applyRulesHandler(dp, nil, c, nil)
	if w := protocolPost(apply, m, "", `{}`); w.Code != 200 {
		t.Fatalf("install: %d %s", w.Code, w.Body)
	}
	before := dp.Protection()
	mutated, fail := 0, false
	ifaces := interfaceApplyHandler(zap.NewNop().Sugar(), nil,
		func(context.Context, []config.Interface, netcfg.ApplyOptions) error {
			mutated++ // first link mutation precedes a later kernel error
			o := subsystem(t, dp.Protection(), protection.SubsystemInterfaces)
			if o.Acknowledged != nil || o.State != protection.DeliveryPending {
				t.Fatalf("prior success survived mutation: %+v", o)
			}
			if fail {
				return errors.New("second address failed")
			}
			return nil
		})
	h := c.admit("interfaces", ifaces)
	for _, failure := range []bool{false, true, false} {
		fail = failure
		w := protocolPost(h, m, "", `[{"name":"lan","device":"test0"}]`)
		want := 200
		if failure {
			want = 400
		}
		if w.Code != want {
			t.Fatalf("interfaces: %d %s", w.Code, w.Body)
		}
		st := dp.Protection()
		o := subsystem(t, st, protection.SubsystemInterfaces)
		if (o.Acknowledged == nil) != failure || st.Installed == nil ||
			*st.Installed != *before.Installed || st.State == "pending" ||
			subsystem(t, st, protection.SubsystemNFT).State != protection.DeliveryReady {
			t.Fatalf("owner retry falsified installation: %+v", st)
		}
	}
	if mutated != 3 {
		t.Fatalf("missing owner attempts: %d", mutated)
	}
	// Changing a resolved address projection requires a fresh attempt.
	if w := protocolPost(h, m, "", `[{"name":"lan","device":"test1"}]`); w.Code != 409 || mutated != 3 {
		t.Fatalf("changed projection reused attempt: %d %s", w.Code, w.Body)
	}
}

func protocolEngine(t *testing.T) *engine.Engine {
	t.Helper()
	dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{Enabled: true, Applier: adoptionApplier{},
		ClearMark: noPolicyMarks}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dp.Close)
	return dp
}

func TestProtectionTrustRetryKeepsInstallation(t *testing.T) {
	dp := protocolEngine(t)
	c := testProtectionCoordinator(t, dp)
	m := protocolMetadata("trust-attempt")
	if w := protocolPost(applyRulesHandler(dp, nil, c, nil), m, "", `{}`); w.Code != 200 {
		t.Fatalf("rules: %d %s", w.Code, w.Body)
	}
	trust := &fakeTrust{}
	h := c.admit("trust", trustHandler(trust))
	for _, failed := range []bool{false, true, false} {
		trust.err = nil
		if failed {
			trust.err = errors.New("delivery failed")
			// The owner no longer confirms its pool; an unchanged live pool is adopted.
			trust.applied.Revision = ""
		}
		w := protocolPost(h, m, "", `{"revision":"none","pem":""}`)
		if (w.Code >= 400) != failed {
			t.Fatalf("trust: %d %s", w.Code, w.Body)
		}
		st := dp.Protection()
		o := subsystem(t, st, protection.SubsystemTrust)
		if st.State == "pending" || (o.Acknowledged == nil) != failed {
			t.Fatalf("trust retry: %+v", st)
		}
		if !failed && (o.Acknowledged.Metadata != m || o.Acknowledged.TrustRevision != "none") {
			t.Fatalf("trust association: %+v", o)
		}
	}
	encoded, err := json.Marshal(dp.Protection())
	if err != nil || !strings.Contains(string(encoded), `"installed"`) {
		t.Fatalf("observation wire: %s %v", encoded, err)
	}
}

func TestProtectionResolvedOwnerInputRequiresFreshAttempt(t *testing.T) {
	for _, phase := range []string{"routing", "services"} {
		t.Run(phase, func(t *testing.T) {
			dp := newCountingDP(t)
			c := testProtectionCoordinator(t, dp)
			resolved, mutations := "device0", 0
			h := c.admit(phase, func(w http.ResponseWriter, r *http.Request) {
				if resolvedPhaseInput(w, r, phase, resolved) {
					mutations++
				}
			})
			m := protocolMetadata("narrowed")
			if w := protocolPost(h, m, "", `{}`); w.Code != 200 {
				t.Fatalf("initial: %d %s", w.Code, w.Body)
			}
			resolved = "device1"
			if w := protocolPost(h, m, "", `{}`); w.Code != 409 || mutations != 1 {
				t.Fatalf("changed resolution admitted: %d %s", w.Code, w.Body)
			}
			fresh := m
			fresh.ApplyID = "recovered"
			if w := protocolPost(h, fresh, string(m.ApplyID), `{}`); w.Code != 200 || mutations != 2 {
				t.Fatalf("fresh resolution: %d %s", w.Code, w.Body)
			}
			resolved = "device0"
			if w := protocolPost(h, m, string(fresh.ApplyID), `{}`); w.Code != 409 || mutations != 2 {
				t.Fatalf("delayed narrowed phase overwrote recovery: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestProtectionOwnershipCallbackFencesReplacement(t *testing.T) {
	dp := newCountingDP(t)
	c := testProtectionCoordinator(t, dp)
	owner := newOwnershipManager(zap.NewNop().Sugar())
	m := protocolMetadata("old-owner")
	h := c.admit("interfaces", func(_ http.ResponseWriter, r *http.Request) {
		owner.applyMu.Lock()
		defer owner.applyMu.Unlock()
		owner.bindDelivery(r, protection.SubsystemInterfaces)
	})
	if w := protocolPost(h, m, "", `[]`); w.Code != 200 {
		t.Fatalf("owner: %d %s", w.Code, w.Body)
	}
	if !owner.currentDelivery(protection.SubsystemInterfaces) {
		t.Fatal("current owner cannot reconcile")
	}
	next := m
	next.ApplyID = "recovery"
	h = c.admit("config", func(http.ResponseWriter, *http.Request) {})
	if w := protocolPost(h, next, string(m.ApplyID), `{}`); w.Code != 200 {
		t.Fatalf("replacement: %d %s", w.Code, w.Body)
	}
	if owner.currentDelivery(protection.SubsystemInterfaces) {
		t.Fatal("superseded owner can mutate replacement")
	}
	before := subsystem(t, dp.Protection(), protection.SubsystemInterfaces)
	owner.publishDelivery(protection.SubsystemInterfaces, false, true)
	after := subsystem(t, dp.Protection(), protection.SubsystemInterfaces)
	if before.Acknowledged == nil || after.Acknowledged == nil || *before.Acknowledged != *after.Acknowledged ||
		before.State != after.State || after.Fault != nil {
		t.Fatalf("delayed owner callback modified replacement: before=%+v after=%+v", before, after)
	}
}
