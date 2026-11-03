// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
	"go.uber.org/zap"
)

type bootstrapDelivery struct {
	mu      sync.Mutex
	logger  *zap.SugaredLogger
	path    string
	pending map[string]users.BootstrapEvent
	ledger  *users.BootstrapLedger
}

func bootstrapPasswordPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "bootstrap", "admin-password")
}

func newBootstrapDelivery(logger *zap.SugaredLogger, dbPath string, ledger *users.BootstrapLedger) *bootstrapDelivery {
	return &bootstrapDelivery{
		logger: logger, path: bootstrapPasswordPath(dbPath),
		pending: make(map[string]users.BootstrapEvent), ledger: ledger,
	}
}

// observe is private delivery, not logging. Never pass an event or password to
// zap/slog: all normal logger cores (including syslog) receive every log entry.
func (d *bootstrapDelivery) observe(event users.BootstrapEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch event.Kind {
	case users.BootstrapIssued:
		// A reset replaces the entire users directory with one fresh admin.
		if event.Reason == "reset" {
			clear(d.pending)
		}
		d.pending[event.UserID] = event
		if _, err := fmt.Fprintf(os.Stdout, "CONTAIND ONE-TIME PASSWORD user=%s password=%s generation=%d (a password change is required at first login)\n",
			event.Username, event.Password, event.Generation); err != nil {
			d.logger.Warnf("failed to deliver bootstrap password to stdout: %v", err)
		}
		d.ledger.Append(users.BootstrapMetadata{
			Username: event.Username, Generation: event.Generation, Reason: event.Reason,
		})
	case users.BootstrapRetired:
		delete(d.pending, event.UserID)
	default:
		return
	}
	if err := d.snapshot(); err != nil {
		d.logger.Warnf("failed to write bootstrap password file %s; stdout remains authoritative: %v", d.path, err)
	}
}

func (d *bootstrapDelivery) snapshot() error {
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("bootstrap path is not a directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".admin-password-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			d.logger.Warnf("failed to remove temporary bootstrap password file: %v", err)
		}
	}()
	defer file.Close()
	// Sort only for stable snapshots; event/audit ordering remains unchanged.
	events := make([]users.BootstrapEvent, 0, len(d.pending))
	for _, event := range d.pending {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Username < events[j].Username })
	for _, event := range events {
		if _, err := fmt.Fprintf(file, "%s %s\n", event.Username, event.Password); err != nil {
			return err
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), d.path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func auditBootstrapDelivery(ctx context.Context, store audit.Store, ledger *users.BootstrapLedger) error {
	for _, metadata := range ledger.Drain() {
		if err := store.Add(ctx, audit.Record{
			Actor: "system", Source: "management", Action: "auth.bootstrap_password.issued",
			Target: metadata.Username, Result: "ok",
			Detail: fmt.Sprintf("generation=%d reason=%s", metadata.Generation, metadata.Reason),
		}); err != nil {
			return err
		}
	}
	return nil
}
