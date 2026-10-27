// SPDX-License-Identifier: Apache-2.0

package services

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// maxDatabaseEntries bounds the ownership walk over the database directory,
// which holds a few signature databases and FreshClam's state files.
const maxDatabaseEntries = 4096

// prepareDir creates dir and, when daemons run as their own account, gives
// it to that account so clamd and FreshClam can write there.
func (m *AVManager) prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if _, uid, gid, ok := m.daemonAccount(); ok {
		return os.Chown(dir, uid, gid)
	}
	return nil
}

// prepareDatabaseDir prepares the database directory and its contents. The
// directory may be a volume kept from an image whose daemon account had
// another uid, so every entry is given to the current account; otherwise
// FreshClam cannot replace databases the old account owns.
func (m *AVManager) prepareDatabaseDir() error {
	dir := m.opts.DatabaseDir
	if err := m.prepareDir(dir); err != nil {
		return err
	}
	if _, uid, gid, ok := m.daemonAccount(); ok {
		return convergeOwnership(dir, uid, gid, maxDatabaseEntries)
	}
	return nil
}

// convergeOwnership gives dir and every entry below it to uid:gid. It never
// follows symbolic links: a link itself is re-owned, and every path resolves
// inside dir. It refuses directories holding more than limit entries. An
// entry removed during the walk, such as a finished FreshClam download, is
// skipped.
func convergeOwnership(dir string, uid, gid, limit int) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	entries := 0
	return fs.WalkDir(root.FS(), ".", func(name string, _ fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if entries++; entries > limit {
			return fmt.Errorf("%s holds more than %d entries", dir, limit)
		}
		if err := root.Lchown(name, uid, gid); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	})
}
