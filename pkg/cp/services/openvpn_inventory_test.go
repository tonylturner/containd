// SPDX-License-Identifier: Apache-2.0
package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func newOpenVPNTestInventory(t *testing.T) *openVPNInventory {
	t.Helper()
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	inv, err := openOpenVPNInventory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return inv
}
func TestOpenVPNInventoryRevocationDurable(t *testing.T) {
	inv := newOpenVPNTestInventory(t)
	alice, err := inv.issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := inv.issue("bob")
	if err != nil {
		t.Fatal(err)
	}
	if alice.ID == bob.ID || alice.Issuer != bob.Issuer {
		t.Fatal("issuer+serial identity broken")
	}
	for _, name := range []string{"alice", "Alice", "ali ce", "../alice"} {
		want := ErrOpenVPNInvalidClientName
		if name == "alice" {
			want = ErrOpenVPNClientNameIssued
		}
		if _, err := inv.issue(name); !errors.Is(err, want) {
			t.Fatalf("issue %s: expected %v, got %v", name, want, err)
		}
	}
	result, err := revokeOpenVPNCredential(inv.dir, alice.ID)
	if err != nil || !result.Revoked {
		t.Fatalf("revoke: %+v %v", result, err)
	}
	inv, err = readOpenVPNInventory(inv.dir)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(inv.CRL)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if crl.CheckSignatureFrom(inv.ca) != nil || crl.ThisUpdate.After(now) || crl.NextUpdate.Before(now.Add(6*24*time.Hour)) || len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != alice.Serial {
		t.Fatalf("invalid signed CRL: %+v", crl)
	}
	before := append([]byte(nil), inv.CRL...)
	second, err := revokeOpenVPNCredential(inv.dir, alice.ID)
	if err != nil || !second.Credential.RevokedAt.Equal(*result.Credential.RevokedAt) {
		t.Fatalf("not idempotent: %+v %v", second, err)
	}
	inv, err = openOpenVPNInventory(inv.dir)
	if err != nil || !bytes.Equal(before, inv.CRL) {
		t.Fatalf("no-op regenerated CRL: %v", err)
	}
	// A foreign issuer cannot revoke a serial belonging to this authority.
	foreign := newOpenVPNTestInventory(t)
	other, err := foreign.issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokeOpenVPNCredential(inv.dir, other.ID); !errors.Is(err, ErrOpenVPNUnknownCredential) {
		t.Fatalf("foreign credential: %v", err)
	}
	replacement, err := inv.issue("alice")
	if err != nil || replacement.ID == alice.ID {
		t.Fatalf("reissue lost serial ownership: %v", err)
	}
	if len(inv.Credentials) != 3 || inv.Credentials[0].RevokedAt == nil {
		t.Fatal("reissue removed tombstone")
	}
}

func TestOpenVPNInventoryConcurrentIssueRevoke(t *testing.T) {
	inv := newOpenVPNTestInventory(t)
	const count = 8
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for n := range count {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			openVPNAuthorityMu.Lock()
			current, err := readOpenVPNInventory(inv.dir)
			var credential OpenVPNCredential
			if err == nil {
				credential, err = current.issue(string(rune('a' + n)))
			}
			openVPNAuthorityMu.Unlock()
			if err == nil {
				_, err = revokeOpenVPNCredential(inv.dir, credential.ID)
			}
			errs <- err
		}(n)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := readOpenVPNInventory(inv.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Credentials) != count {
		t.Fatal("lost concurrent issuance")
	}
	for _, c := range reopened.Credentials {
		if c.RevokedAt == nil {
			t.Fatal("lost concurrent revocation")
		}
	}
	if !reopened.crlCurrent(time.Now()) {
		t.Fatal("CRL missing concurrent revocation")
	}
}

func TestOpenVPNInventoryCrashRepairAndRenewal(t *testing.T) {
	inv := newOpenVPNTestInventory(t)
	c, err := inv.issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between the durable tombstone and signed CRL publication.
	now := time.Now().UTC()
	inv.Credentials[0].RevokedAt = &now
	if err := inv.save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openOpenVPNInventory(inv.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.ensureCRL(now); err != nil {
		t.Fatal(err)
	}
	if !reopened.crlCurrent(now) || reopened.Credentials[0].ID != c.ID {
		t.Fatal("crash lost tombstone")
	}
	original := append([]byte(nil), reopened.CRL...)
	// Reopen/apply after a long outage must renew before starting a daemon.
	future := now.Add(openVPNCRLLifetime - openVPNCRLRenewBefore + time.Minute)
	if err := reopened.ensureCRL(future); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, reopened.CRL) || !reopened.crlCurrent(future) {
		t.Fatal("expired CRL not renewed")
	}
	// Losing issuer material must fail, never generate a replacement CA.
	originalCA, err := os.ReadFile(filepath.Join(inv.dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(inv.dir, "ca.key"), filepath.Join(inv.dir, "lost.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := openOpenVPNInventory(inv.dir); err == nil {
		t.Fatal("missing issuer silently replaced")
	}
	after, err := os.ReadFile(filepath.Join(inv.dir, "ca.crt"))
	if err != nil || !bytes.Equal(originalCA, after) {
		t.Fatalf("CA replaced: %v", err)
	}
}

func TestOpenVPNInventoryUnknownDownloadIsReadOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", root)
	m := NewVPNManager(filepath.Join(root, "services"))
	if _, err := m.DownloadOpenVPNClient(context.Background(), "missing"); !errors.Is(err, ErrOpenVPNServerNotActive) {
		t.Fatalf("inactive download: %v", err)
	}
	if _, err := m.CreateOpenVPNClient(context.Background(), "alice"); !errors.Is(err, ErrOpenVPNServerNotActive) {
		t.Fatalf("inactive create: %v", err)
	}
	if got, err := m.ListOpenVPNClients(context.Background()); err != nil || len(got.Clients) != 0 || !got.RevocationsApplied {
		t.Fatalf("empty list: %v %v", got, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read created PKI: %v %v", entries, err)
	}
}

func TestOpenVPNInventoryDownloadErrors(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", root)
	inv, err := openOpenVPNInventory(filepath.Join(root, "managed", "server", "pki"))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := inv.issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	m := NewVPNManager(filepath.Join(root, "services"))
	m.lastCfg.OpenVPN = config.OpenVPNConfig{Enabled: true, Mode: "server", Server: &config.OpenVPNManagedServerConfig{
		ListenZone: "wan", TunnelCIDR: "10.9.0.0/24", PublicEndpoint: "vpn.example.com",
	}}
	if _, err := m.DownloadOpenVPNClient(context.Background(), "missing"); !errors.Is(err, ErrOpenVPNUnknownCredential) {
		t.Fatalf("unknown download: %v", err)
	}
	if _, err := revokeOpenVPNCredential(inv.dir, credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DownloadOpenVPNClient(context.Background(), credential.ID); !errors.Is(err, ErrOpenVPNCredentialRevoked) {
		t.Fatalf("revoked download: %v", err)
	}
}

func TestOpenVPNInventoryLegacyAdoptionAndIntegrity(t *testing.T) {
	dir := t.TempDir()
	caPath, keyPath, err := EnsureOpenVPNCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPath, _, err := EnsureOpenVPNClientCert(dir, caPath, keyPath, "legacy-client")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseOpenVPNCertificate(string(original))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the pre-inventory directory layout while preserving the original
	// certificate, private key and issuer exactly, including its canonical CN.
	if err := os.Rename(filepath.Join(dir, "inventory.json"), filepath.Join(dir, "pre-upgrade.json")); err != nil {
		t.Fatal(err)
	}
	inv, err := openOpenVPNInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Credentials) != 1 || inv.Credentials[0].ID != credentialID(inv.Issuer, cert) || inv.Credentials[0].Certificate != string(original) {
		t.Fatal("legacy adoption reissued credential")
	}
	inv.Credentials[0].Serial = inv.Credentials[0].Serial + "0"
	if err := inv.validate(); err == nil {
		t.Fatal("serial metadata not tied to signed certificate")
	}
}

func TestOpenVPNInventoryRevocationPublicationFailure(t *testing.T) {
	inv := newOpenVPNTestInventory(t)
	c, err := inv.issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inv.dir, "crl.pem")
	if err := os.Rename(path, path+".before"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := revokeOpenVPNCredential(inv.dir, c.ID)
	if err == nil || !result.Revoked || result.Applied {
		t.Fatalf("publication failure lost durable result: %+v %v", result, err)
	}
	reopened, err := readOpenVPNInventory(inv.dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Credentials[0].RevokedAt == nil {
		t.Fatal("publication failure removed tombstone")
	}
	if err := os.Rename(path, path+".blocked"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ensureCRL(time.Now()); err != nil {
		t.Fatal(err)
	}
	if !reopened.crlCurrent(time.Now()) {
		t.Fatal("publication repair lost revocation")
	}
}
