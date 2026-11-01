// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"golang.org/x/crypto/ssh"
)

type failedSSHAudit struct {
	audit.ObservableStore
	mu      sync.Mutex
	records []audit.Record
}

func (s *failedSSHAudit) Add(_ context.Context, r audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return errors.New("audit unavailable")
}
func (s *failedSSHAudit) snapshot() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...)
}

func TestAuditSSHFailuresDoNotPreventDenialCredentialLoginLogout(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, users, _ := newAssuranceServer(t)
	raw, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	backend := &failedSSHAudit{ObservableStore: raw}
	observed := audit.NewObservedStore(backend)
	srv.opts.AuditStore = observed
	addr := serveSSH(t, srv)
	if client, err := dialSSH(addr, "containd", nil, ssh.Password("wrong")); err == nil {
		_ = client.Close()
		t.Fatal("invalid credential accepted")
	}
	fresh := sshTestValue("observed-forced-change")
	ki := &scriptedKI{answers: [][]string{{fresh, fresh}}}
	client, err := dialSSH(addr, "containd", nil, ssh.Password("containd"), ki.method(1))
	if err != nil {
		t.Fatal("audit failure blocked credential change/login", err)
	}
	// Both command execution and interactive credentials share the observed path.
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Run("help"); err != nil {
		t.Fatal(err)
	}
	_ = session.Close()
	_ = client.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		records := backend.snapshot()
		found := map[string]bool{}
		for _, rec := range records {
			if rec.Source != "ssh" || rec.Actor != "containd" {
				t.Fatalf("identity lost: %+v", rec)
			}
			found[rec.Action+":"+rec.Result] = true
		}
		status := observed.AuditStatus()
		if found["ssh.login:denied"] && found["auth.password.change:success"] && found["ssh.login:success"] && found["ssh.logout:success"] && found["cli.execute:success"] && status.Failures == uint64(len(records)) {
			if status.State != evidence.StateDegraded {
				t.Fatalf("%+v", status)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing SSH observations: %+v %+v", records, status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, err := users.GetByUsername(context.Background(), "containd")
	if err != nil || u.MustChangePassword {
		t.Fatalf("password mutation rolled back: %+v %v", u, err)
	}
	if err := users.CheckCurrentPassword(context.Background(), u.ID, fresh, time.Now()); err != nil {
		t.Fatal(err)
	}
}
