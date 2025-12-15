//go:build !linux

package dhcpd

import (
	"context"
	"fmt"

	"github.com/containd/containd/pkg/cp/config"
)

type Lease struct {
	Iface     string `json:"iface"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	ExpiresAt string `json:"expiresAt"`
	Hostname  string `json:"hostname,omitempty"`
}

type Manager struct {
	OnEvent func(kind string, attrs map[string]any)
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) SetOnEvent(fn func(kind string, attrs map[string]any)) {
	if m == nil {
		return
	}
	m.OnEvent = fn
}

func (m *Manager) Apply(ctx context.Context, cfg config.DHCPConfig, ifaces []config.Interface) error {
	_ = ctx
	_ = cfg
	_ = ifaces
	return fmt.Errorf("dhcpd not supported on this platform")
}

func (m *Manager) Leases() []Lease { return nil }

func (m *Manager) Status() map[string]any {
	return map[string]any{"enabled": false, "note": "dhcpd not supported on this platform"}
}
