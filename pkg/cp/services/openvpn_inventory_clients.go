// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// OpenVPNClientList separates durable credentials from runtime CRL acknowledgement.
type OpenVPNClientList struct {
	Clients            []OpenVPNCredential `json:"clients"`
	RevocationsApplied bool                `json:"revocationsApplied"`
}

func (m *VPNManager) ListOpenVPNClients(ctx context.Context) (OpenVPNClientList, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return OpenVPNClientList{}, err
	}
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	inv, err := readOpenVPNInventory(filepath.Join(openVPNManagedServerDir(), "pki"))
	if os.IsNotExist(err) {
		return OpenVPNClientList{Clients: []OpenVPNCredential{}, RevocationsApplied: true}, nil
	}
	if err != nil {
		return OpenVPNClientList{}, err
	}
	m.mu.Lock()
	applied := m.ovpnRunning && m.ovpnCRLNumber > 0 && m.ovpnCRLNumber == inv.CRLNumber
	m.mu.Unlock()
	clients := inv.list()
	for _, c := range clients {
		if c.RevokedAt != nil {
			return OpenVPNClientList{Clients: clients, RevocationsApplied: applied}, nil
		}
	}
	return OpenVPNClientList{Clients: clients, RevocationsApplied: true}, nil
}
func (m *VPNManager) CreateOpenVPNClient(ctx context.Context, name string) (OpenVPNCredential, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return OpenVPNCredential{}, err
	}
	cfg := m.Current().OpenVPN
	if !cfg.Enabled || cfg.Mode != "server" || cfg.Server == nil {
		return OpenVPNCredential{}, fmt.Errorf("%w", ErrOpenVPNServerNotActive)
	}
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	inv, err := readOpenVPNInventory(filepath.Join(openVPNManagedServerDir(), "pki"))
	if err != nil {
		return OpenVPNCredential{}, err
	}
	return inv.issue(name)
}
func (m *VPNManager) DownloadOpenVPNClient(ctx context.Context, id string) ([]byte, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := m.Current().OpenVPN
	if !cfg.Enabled || cfg.Mode != "server" || cfg.Server == nil {
		return nil, fmt.Errorf("%w", ErrOpenVPNServerNotActive)
	}
	// Validate the endpoint before embedding it. No issuance, repair or CRL
	// renewal is reachable through a read-only download.
	if err := config.ValidateOpenVPNRemote(cfg.Server.PublicEndpoint); err != nil {
		return nil, err
	}
	opts, err := validateOpenVPNManagedServer(cfg.Server)
	if err != nil {
		return nil, err
	}
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	inv, err := readOpenVPNInventory(filepath.Join(openVPNManagedServerDir(), "pki"))
	if err != nil {
		return nil, err
	}
	c, err := inv.find(id)
	if err != nil {
		return nil, err
	}
	if c.RevokedAt != nil {
		return nil, fmt.Errorf("%w", ErrOpenVPNCredentialRevoked)
	}
	var b strings.Builder
	b.WriteString("client\ndev tun\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth-nocache\n")
	proto := "udp"
	if opts.proto == "tcp" {
		proto = "tcp-client"
	}
	fmt.Fprintf(&b, "proto %s\nremote %s %d\n", proto, cfg.Server.PublicEndpoint, opts.port)
	for _, material := range []struct{ name, value string }{{"ca", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inv.ca.Raw}))}, {"cert", c.Certificate}, {"key", c.PrivateKey}} {
		fmt.Fprintf(&b, "<%s>\n%s</%s>\n", material.name, material.value, material.name)
	}
	return []byte(b.String()), nil
}
