// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// RuntimeRecord is the management this process bound: its listeners and
// what they serve. Management writes it for local processes outside the
// management process, such as containd cli, so they call the same
// listeners as the console and SSH CLI sessions.
type RuntimeRecord struct {
	Listeners config.ManagementListeners `json:"listeners"`
	Served    httpapi.ServedManagement   `json:"served"`
}

// RuntimeRecordPath is run/management.json in the configuration store's
// directory, which CONTAIND_CONFIG_DB selects.
func RuntimeRecordPath() string {
	return filepath.Join(filepath.Dir(configDBPath()), "run", "management.json")
}

// writeRuntimeRecord replaces the record at path atomically, in a directory
// only the management user can open.
func writeRuntimeRecord(path string, rec RuntimeRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll keeps the mode of a directory that already exists.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".management-*.json")
	if err != nil {
		return err
	}
	// After the rename the temporary name no longer exists.
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// readRuntimeRecord reads the record at path. A missing or unreadable
// record means no management process has bound listeners there.
func readRuntimeRecord(path string) (RuntimeRecord, error) {
	var rec RuntimeRecord
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &rec)
	}
	if err != nil {
		return RuntimeRecord{}, fmt.Errorf("management is not running: no usable runtime record at %s: %w", path, err)
	}
	return rec, nil
}

// LocalManagementAPI is the base URL and client a local process outside the
// management process calls management with. It adopts the runtime record
// management wrote and selects through httpapi.LoopbackManagementAPI: the
// bound HTTP listener unless it redirects, else the bound HTTPS listener
// pinned to the certificate it serves, never following redirects. A record
// left by a management process that crashed fails as an ordinary
// connection error.
func LocalManagementAPI() (string, *http.Client, error) {
	rec, err := readRuntimeRecord(RuntimeRecordPath())
	if err != nil {
		return "", nil, err
	}
	config.SetBoundManagementListeners(rec.Listeners)
	httpapi.SetServedManagement(rec.Served)
	baseURL, client, err := httpapi.LoopbackManagementAPI()
	if err != nil {
		return "", nil, fmt.Errorf("management runtime record %s: %w", RuntimeRecordPath(), err)
	}
	return baseURL, client, nil
}

// runtimeRecordPublisher writes the record whenever management publishes
// bound listeners, and removes it when management stops.
type runtimeRecordPublisher struct {
	path   string
	served httpapi.ServedManagement
}

// publish writes the listeners management has bound so far. A failure is
// returned for logging: management keeps serving, and local CLIs report
// that it is not running.
func (p *runtimeRecordPublisher) publish() error {
	return writeRuntimeRecord(p.path, RuntimeRecord{Listeners: config.BoundManagementListeners(), Served: p.served})
}

func (p *runtimeRecordPublisher) remove() error {
	if err := os.Remove(p.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
