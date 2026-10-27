// SPDX-License-Identifier: Apache-2.0

package services

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// databaseTree builds a database directory with a nested FreshClam work
// directory and links that point outside the tree. It returns the database
// directory and the outside file.
func databaseTree(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "clamav")
	outside := filepath.Join(base, "outside.conf")
	for _, p := range []string{filepath.Join(dir, "tmp.1"), filepath.Join(base, "outside.d")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{filepath.Join(dir, "daily.cld"), filepath.Join(dir, "tmp.1", "main.cvd"), outside} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "outside.d"), filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	return dir, outside
}

func lstatOwner(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

func TestConvergeOwnershipBounds(t *testing.T) {
	dir, _ := databaseTree(t)
	uid, gid := os.Getuid(), os.Getgid()
	// The directory, two files, the work directory and two links.
	if err := convergeOwnership(dir, uid, gid, 6); err != nil {
		t.Fatalf("convergeOwnership: %v", err)
	}
	if err := convergeOwnership(dir, uid, gid, 5); err == nil || !strings.Contains(err.Error(), "more than 5 entries") {
		t.Fatalf("convergeOwnership over the limit = %v", err)
	}
	if err := convergeOwnership(filepath.Join(dir, "missing"), uid, gid, 6); err == nil {
		t.Fatal("convergeOwnership accepted a missing directory")
	}
}

// TestConvergeOwnershipReownsTree needs root to change owners; the Linux race
// container runs it.
func TestConvergeOwnershipReownsTree(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file owners requires root")
	}
	dir, outside := databaseTree(t)
	const oldID, newID = 1234, 4321
	inside := []string{dir, filepath.Join(dir, "daily.cld"), filepath.Join(dir, "tmp.1"), filepath.Join(dir, "tmp.1", "main.cvd"), filepath.Join(dir, "link.conf"), filepath.Join(dir, "linkdir")}
	for _, p := range inside {
		if err := os.Lchown(p, oldID, oldID); err != nil {
			t.Fatal(err)
		}
	}
	if err := convergeOwnership(dir, newID, newID, maxDatabaseEntries); err != nil {
		t.Fatalf("convergeOwnership: %v", err)
	}
	for _, p := range inside {
		if uid, gid := lstatOwner(t, p); uid != newID || gid != newID {
			t.Fatalf("%s owned by %d:%d, want %d:%d", p, uid, gid, newID, newID)
		}
	}
	for _, p := range []string{outside, filepath.Dir(outside) + "/outside.d"} {
		if uid, gid := lstatOwner(t, p); uid != 0 || gid != 0 {
			t.Fatalf("link target %s re-owned to %d:%d", p, uid, gid)
		}
	}
}
