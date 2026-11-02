// SPDX-License-Identifier: Apache-2.0

package demo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreferenceResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo.json")
	p, err := Load(path)
	if err != nil || p != Auto {
		t.Fatal(p, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"preference":"auto"}` {
		t.Fatal(string(data), err)
	}
	for _, p := range []Preference{On, Off, Auto} {
		if err := Save(path, p); err != nil {
			t.Fatal(err)
		}
		if got, err := Load(path); err != nil || got != p {
			t.Fatal(got, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal(info, err)
		}
	}
	for _, data := range []string{`{`, `{"preference":"unknown"}`, `{}`, `null`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if p, err := Load(path); p != Off || err == nil {
			t.Fatal(p, err)
		}
	}
	if p, err := Load(t.TempDir()); p != Off || err == nil {
		t.Fatal(p, err)
	}
	if err := Save(path, "bad"); err == nil {
		t.Fatal("invalid preference accepted")
	}
}
