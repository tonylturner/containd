// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDNSManagerValidate(t *testing.T) {
	mgr := NewDNSManager(t.TempDir())
	mgr.CheckConfPath = ""

	tests := []struct {
		name    string
		cfg     config.DNSConfig
		wantErr string
	}{
		{
			name: "disabled config allowed",
			cfg:  config.DNSConfig{},
		},
		{
			name: "invalid listen port",
			cfg: config.DNSConfig{
				Enabled:    true,
				ListenPort: 70000,
			},
			wantErr: "dns listenPort invalid",
		},
		{
			name: "empty upstream rejected",
			cfg: config.DNSConfig{
				Enabled:         true,
				ListenPort:      53,
				UpstreamServers: []string{"1.1.1.1", "   "},
			},
			wantErr: "dns upstreamServers contains empty entry",
		},
		{
			name: "valid config without validator binary",
			cfg: config.DNSConfig{
				Enabled:         true,
				ListenPort:      5353,
				CacheSizeMB:     32,
				UpstreamServers: []string{"1.1.1.1", "8.8.8.8"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.Validate(context.Background(), tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
