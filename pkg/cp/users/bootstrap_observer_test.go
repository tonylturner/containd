// SPDX-License-Identifier: Apache-2.0

package users

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBootstrapObserverPerStore(t *testing.T) {
	first, second := newTestStore(t), newTestStore(t)
	var got []BootstrapEvent
	event := BootstrapEvent{Kind: BootstrapIssued, Username: "admin", UserID: "id", Generation: 1, Reason: "seed", Password: "private-password"}
	first.SetBootstrapObserver(func(e BootstrapEvent) {
		got = append(got, e)
		// A callback can replace itself without deadlocking.
		first.SetBootstrapObserver(nil)
	})
	second.emitBootstrapEvents([]BootstrapEvent{event})
	if len(got) != 0 {
		t.Fatal("observer leaked between stores")
	}
	first.emitBootstrapEvents([]BootstrapEvent{event})
	first.emitBootstrapEvents([]BootstrapEvent{event})
	if !reflect.DeepEqual(got, []BootstrapEvent{event}) {
		t.Fatalf("events = %+v", got)
	}
	data, err := json.Marshal(event)
	if err != nil || strings.Contains(string(data), event.Password) {
		t.Fatal("JSON must not serialize the password")
	}
}

func TestBootstrapObserverLedger(t *testing.T) {
	var ledger BootstrapLedger
	if ledger.Drain() != nil {
		t.Fatal("empty drain must return nil")
	}
	first := BootstrapMetadata{Username: "admin", Generation: 1, Reason: "seed"}
	second := BootstrapMetadata{Username: "admin", Generation: 2, Reason: "reissue"}
	ledger.Append(first)
	ledger.Append(second)
	drained := ledger.Drain()
	if !reflect.DeepEqual(drained, []BootstrapMetadata{first, second}) || ledger.Drain() != nil {
		t.Fatalf("drain = %+v", drained)
	}
	ledger.Append(first)
	drained[0].Username = "changed"
	if got := ledger.Drain(); !reflect.DeepEqual(got, []BootstrapMetadata{first}) {
		t.Fatalf("drained records alias pending records: %+v", got)
	}
	typ := reflect.TypeFor[BootstrapMetadata]()
	if typ.NumField() != 3 {
		t.Fatal("ledger metadata contract changed")
	}
	for _, name := range []string{"Username", "Generation", "Reason"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Fatalf("missing metadata field %s", name)
		}
	}
}
