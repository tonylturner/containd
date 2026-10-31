// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEngineCredentialsCommand(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_SECRET", hex.EncodeToString([]byte("public engine transport test key")))
	if err := runEngineCredentials(nil); err == nil {
		t.Fatal("missing directory accepted")
	}
	if err := runEngineCredentials([]string{"a", "b"}); err == nil {
		t.Fatal("extra arguments accepted")
	}
	dir := t.TempDir()
	if err := runEngineCredentials([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if err := runEngineCredentials([]string{dir}); err == nil {
		t.Fatal("overwrote credentials")
	}
	if _, err := os.Stat(filepath.Join(dir, "client.key")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_ENGINE_SECRET", "")
	if err := runEngineCredentials([]string{t.TempDir()}); err == nil {
		t.Fatal("missing secret accepted")
	}
}
