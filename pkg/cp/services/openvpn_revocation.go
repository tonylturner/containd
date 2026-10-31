// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"sort"
	"time"
)

const openVPNCRLLifetime = 7 * 24 * time.Hour
const openVPNCRLRenewBefore = 24 * time.Hour

// OpenVPNRevokeResult must be returned even on error. Revoked means the
// tombstone is durable; Applied means the daemon has restarted with that CRL.
// A runtime error must never undo a durable revocation.
type OpenVPNRevokeResult struct {
	Credential OpenVPNCredential `json:"credential"`
	Revoked    bool              `json:"revoked"`
	Applied    bool              `json:"applied"`
}

func (i *openVPNInventory) crlCurrent(now time.Time) bool {
	block, _ := pem.Decode(i.CRL)
	if block == nil {
		return false
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || crl.CheckSignatureFrom(i.ca) != nil || crl.ThisUpdate.After(now) || !crl.NextUpdate.After(now.Add(openVPNCRLRenewBefore)) || crl.Number == nil || crl.Number.Cmp(big.NewInt(i.CRLNumber)) != 0 {
		return false
	}
	revoked := map[string]time.Time{}
	for _, c := range i.Credentials {
		if c.RevokedAt != nil {
			revoked[c.Serial] = *c.RevokedAt
		}
	}
	if len(revoked) != len(crl.RevokedCertificateEntries) {
		return false
	}
	for _, entry := range crl.RevokedCertificateEntries {
		at, ok := revoked[entry.SerialNumber.Text(16)]
		if !ok || !at.Truncate(time.Second).Equal(entry.RevocationTime) {
			return false
		}
		delete(revoked, entry.SerialNumber.Text(16))
	}
	return len(revoked) == 0
}

func (i *openVPNInventory) ensureCRL(now time.Time) error {
	if !i.crlCurrent(now) {
		entries := make([]x509.RevocationListEntry, 0)
		for _, c := range i.Credentials {
			if c.RevokedAt == nil {
				continue
			}
			serial, ok := new(big.Int).SetString(c.Serial, 16)
			if !ok {
				return fmt.Errorf("invalid inventory serial")
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: *c.RevokedAt})
		}
		sort.Slice(entries, func(a, b int) bool { return entries[a].SerialNumber.Cmp(entries[b].SerialNumber) < 0 })
		i.CRLNumber++
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(i.CRLNumber), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(openVPNCRLLifetime), RevokedCertificateEntries: entries}, i.ca, i.key)
		if err != nil {
			return err
		}
		i.CRL = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
		if err := i.save(); err != nil {
			return err
		}
	}
	// Repair missing/stale derived material after a crash, without changing the
	// signed CRL or revocation state (and therefore without a needless restart).
	return atomicWriteFile(filepath.Join(i.dir, "crl.pem"), i.CRL, 0o600)
}

func (m *VPNManager) RevokeOpenVPNClient(ctx context.Context, id string) (OpenVPNRevokeResult, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	result, err := revokeOpenVPNCredential(filepath.Join(openVPNManagedServerDir(), "pki"), id)
	if err != nil {
		return result, err
	}
	// Do not use a caller-supplied candidate: only the currently applied server
	// can confirm disconnection. Revocation survives cancellation/restart failure.
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("revoked, runtime not confirmed: %w", err)
	}
	cfg := m.Current()
	if !cfg.OpenVPN.Enabled || cfg.OpenVPN.Mode != "server" || cfg.OpenVPN.Server == nil {
		return result, fmt.Errorf("revoked, runtime not confirmed: managed server is not active")
	}
	if err := m.applyVPNLocked(ctx, cfg); err != nil {
		return result, fmt.Errorf("revoked, runtime not confirmed: %w", err)
	}
	result.Applied = true
	return result, nil
}

func revokeOpenVPNCredential(dir, id string) (OpenVPNRevokeResult, error) {
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	result := OpenVPNRevokeResult{}
	inv, err := readOpenVPNInventory(dir)
	if err != nil {
		return result, err
	}
	c, err := inv.find(id)
	if err != nil {
		return result, err
	}
	if c.RevokedAt == nil {
		now := time.Now().UTC()
		c.RevokedAt = &now
		// Commit the tombstone first. If signing/publication fails, reopen repairs
		// the CRL from this durable state; there is no compensating unrevocation.
		if err := inv.save(); err != nil {
			return result, err
		}
	}
	result.Credential, result.Revoked = c.OpenVPNCredential, true
	if err := inv.ensureCRL(time.Now().UTC()); err != nil {
		return result, fmt.Errorf("revoked, runtime not confirmed: %w", err)
	}
	return result, nil
}

func (m *VPNManager) renewOpenVPNCRL(done <-chan struct{}) {
	interval := m.crlCheckInterval
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			m.applyMu.Lock()
			select {
			case <-done:
				m.applyMu.Unlock()
				return
			default:
			}
			cfg := m.Current()
			var err error
			if cfg.OpenVPN.Enabled && cfg.OpenVPN.Mode == "server" && cfg.OpenVPN.Server != nil {
				err = m.applyVPNLocked(context.Background(), cfg)
			}
			m.applyMu.Unlock()
			if err != nil {
				m.emit("service.vpn.openvpn.crl_renewal_failed", map[string]any{"error": err.Error()})
			}
		}
	}
}
