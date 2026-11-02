// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalFilesystemCapability(t *testing.T) {
	allowed := WithLocalFilesystem(context.Background(), true)
	if err := requireLocalFilesystem(allowed); err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{context.Background(), WithLocalFilesystem(allowed, false)} {
		if err := requireLocalFilesystem(ctx); !errors.Is(err, ErrLocalFilesystemUnavailable) {
			t.Fatalf("missing or revoked capability allowed: %v", err)
		}
	}
	cancelled, cancel := context.WithCancel(allowed)
	cancel()
	if err := requireLocalFilesystem(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context allowed: %v", err)
	}
}

func TestLocalFilesystemCommandsRefuseBeforeIO(t *testing.T) {
	root := t.TempDir()
	credential := filepath.Join(root, "credential")
	if err := os.WriteFile(credential, []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "download")
	commands := []struct {
		name string
		args []string
	}{
		{"download backup", []string{"id", target}},
		{"download openvpn client", []string{"id", target}},
		{"set vpn wireguard private-key-file", []string{credential}},
		{"set vpn openvpn client password-file", []string{credential}},
		{"set vpn openvpn client ca-file", []string{credential}},
		{"set vpn openvpn client cert-file", []string{credential}},
		{"set vpn openvpn client key-file", []string{credential}},
		{"import config", []string{credential}},
		{"analyze pcap", []string{credential}},
		{"convert sigma", []string{credential}},
		{"diag capture", []string{"lo", "1", target}},
	}
	api := &API{BaseURL: "http://appliance", Client: opsClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("filesystem refusal made an API request")
		return nil, nil
	})}
	registry := NewRegistry(nil, api)
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			admin := WithRole(context.Background(), "admin")
			for _, ctx := range []context.Context{admin, WithLocalFilesystem(WithLocalFilesystem(admin, true), false)} {
				err := registry.Execute(ctx, command.name, io.Discard, command.args)
				if !errors.Is(err, ErrLocalFilesystemUnavailable) {
					t.Fatalf("did not refuse before reading file: %v", err)
				}
			}
		})
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused command created a file: %v", err)
	}
}

func TestLocalFilesystemDoesNotGrantAdmin(t *testing.T) {
	registry := NewRegistry(nil, &API{})
	for _, name := range []string{"download backup", "download openvpn client"} {
		if strings.Contains(strings.Join(registry.CommandsForRole(RoleView), "\n"), name) {
			t.Fatalf("viewer command list includes %s", name)
		}
		err := registry.Execute(WithLocalFilesystem(WithRole(context.Background(), "view"), true), name, io.Discard, []string{"id", "file"})
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("filesystem capability granted admin for %s: %v", name, err)
		}
	}
}
