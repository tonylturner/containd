// SPDX-License-Identifier: Apache-2.0
package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// All authority operations, including legacy PKI entry points, share this lock.
// Only the management process owns this directory; do not share a writable PKI
// volume between management processes.
var openVPNAuthorityMu sync.Mutex

// OpenVPNCredential identifies one issued certificate. A name may be reissued
// only after revocation; the old issuer+serial tombstone is never replaced.
type OpenVPNCredential struct {
	ID        string     `json:"id"`
	Issuer    string     `json:"issuer"`
	Serial    string     `json:"serial"`
	Name      string     `json:"name"`
	IssuedAt  time.Time  `json:"issuedAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}
type openVPNIssued struct {
	OpenVPNCredential
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}
type openVPNInventory struct {
	Version     int             `json:"version"`
	Issuer      string          `json:"issuer"`
	Credentials []openVPNIssued `json:"credentials"`
	CRL         []byte          `json:"crl"`
	CRLNumber   int64           `json:"crlNumber"`
	dir         string
	ca          *x509.Certificate
	key         *ecdsa.PrivateKey
}

func issuerID(ca *x509.Certificate) string {
	sum := sha256.Sum256(ca.Raw)
	return hex.EncodeToString(sum[:])
}
func credentialID(issuer string, cert *x509.Certificate) string {
	return issuer + ":" + cert.SerialNumber.Text(16)
}
func validOpenVPNName(name string) bool {
	return name != "" && name == sanitizeClientName(name) && len(name) <= 64
}

// openOpenVPNInventory initializes or adopts existing PKI, never rotates it.
// Callers hold openVPNAuthorityMu. The inventory contains the signed CRL and
// all key material in one synced snapshot; daemon files are derived outputs.
func openOpenVPNInventory(dir string) (*openVPNInventory, error) {
	inv, err := readOpenVPNInventory(dir)
	if err == nil {
		return inv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// A missing inventory is allowed for legacy adoption, not a missing CA under
	// an existing inventory. readOpenVPNInventory returns a distinct error there.
	caPath, keyPath, err := ensureOpenVPNCA(dir)
	if err != nil {
		return nil, err
	}
	ca, key, err := loadCertAndKey(caPath, keyPath)
	if err != nil {
		return nil, err
	}
	if _, _, err = ensureOpenVPNServerCert(dir, caPath, keyPath); err != nil {
		return nil, err
	}
	inv = &openVPNInventory{Version: 1, Issuer: issuerID(ca), dir: dir, ca: ca, key: key}
	paths, err := filepath.Glob(filepath.Join(dir, "clients", "*.crt"))
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		cert, key, err := loadCertAndKey(path, strings.TrimSuffix(path, ".crt")+".key")
		if err != nil {
			return nil, fmt.Errorf("legacy client pair invalid: %w", err)
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			return nil, fmt.Errorf("legacy client issuer mismatch: %w", err)
		}
		name := strings.TrimSuffix(filepath.Base(path), ".crt")
		if !validOpenVPNName(name) || cert.Subject.CommonName != name {
			return nil, fmt.Errorf("legacy client name mismatch")
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		inv.Credentials = append(inv.Credentials, openVPNIssued{OpenVPNCredential: inv.credential(cert, name), Certificate: string(certPEM), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))})
	}
	if err := inv.validate(); err != nil {
		return nil, err
	}
	if err := inv.ensureCRL(time.Now().UTC()); err != nil {
		return nil, err
	}
	return inv, nil
}

// readOpenVPNInventory never creates, renews, repairs or writes anything.
func readOpenVPNInventory(dir string) (*openVPNInventory, error) {
	b, err := os.ReadFile(filepath.Join(dir, "inventory.json"))
	if err != nil {
		return nil, err
	}
	var inv openVPNInventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("invalid OpenVPN inventory: %w", err)
	}
	ca, key, err := loadCertAndKey(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("inventory issuer unavailable (refusing replacement): %v", err)
	}
	inv.dir, inv.ca, inv.key = dir, ca, key
	if err := inv.validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (i *openVPNInventory) validate() error {
	if i.Version != 1 || i.Issuer != issuerID(i.ca) || !i.ca.IsCA || i.ca.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("inventory issuer/version mismatch")
	}
	seen := make(map[string]bool)
	names := make(map[string]bool)
	for _, c := range i.Credentials {
		cert, err := parseOpenVPNCertificate(c.Certificate)
		if err != nil {
			return err
		}
		keyBlock, _ := pem.Decode([]byte(c.PrivateKey))
		if keyBlock == nil {
			return fmt.Errorf("missing client key")
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(&key.PublicKey) || cert.CheckSignatureFrom(i.ca) != nil || c.ID != credentialID(i.Issuer, cert) || c.Serial != cert.SerialNumber.Text(16) || c.Issuer != i.Issuer || c.Name != cert.Subject.CommonName || !validOpenVPNName(c.Name) || seen[c.ID] {
			return fmt.Errorf("inventory credential integrity failure")
		}
		if c.RevokedAt == nil && names[c.Name] {
			return fmt.Errorf("duplicate active client name")
		}
		seen[c.ID] = true
		if c.RevokedAt == nil {
			names[c.Name] = true
		}
	}
	return nil
}
func parseOpenVPNCertificate(text string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(text))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid client certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}
func (i *openVPNInventory) credential(cert *x509.Certificate, name string) OpenVPNCredential {
	return OpenVPNCredential{ID: credentialID(i.Issuer, cert), Issuer: i.Issuer, Serial: cert.SerialNumber.Text(16), Name: name, IssuedAt: cert.NotBefore, ExpiresAt: cert.NotAfter}
}
func (i *openVPNInventory) save() error {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(i.dir, "inventory.json"), b, 0o600)
}
func (i *openVPNInventory) find(id string) (*openVPNIssued, error) {
	for n := range i.Credentials {
		if i.Credentials[n].ID == id {
			return &i.Credentials[n], nil
		}
	}
	return nil, fmt.Errorf("unknown OpenVPN credential")
}
func (i *openVPNInventory) list() []OpenVPNCredential {
	out := make([]OpenVPNCredential, 0, len(i.Credentials))
	for _, c := range i.Credentials {
		out = append(out, c.OpenVPNCredential)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}
func (i *openVPNInventory) issue(name string) (OpenVPNCredential, error) {
	if !validOpenVPNName(name) {
		return OpenVPNCredential{}, fmt.Errorf("client name must be an exact lowercase filename-safe name (1-64 characters)")
	}
	for _, c := range i.Credentials {
		if c.Name == name && c.RevokedAt == nil {
			return OpenVPNCredential{}, fmt.Errorf("client name already issued")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return OpenVPNCredential{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return OpenVPNCredential{}, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name, Organization: []string{"containd"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(3 * 365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.ca, &key.PublicKey, i.key)
	if err != nil {
		return OpenVPNCredential{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return OpenVPNCredential{}, err
	}
	id := credentialID(i.Issuer, cert)
	for _, c := range i.Credentials {
		if c.ID == id {
			return OpenVPNCredential{}, fmt.Errorf("certificate serial collision")
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return OpenVPNCredential{}, err
	}
	c := openVPNIssued{OpenVPNCredential: i.credential(cert, name), Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))}
	i.Credentials = append(i.Credentials, c)
	if err := i.save(); err != nil {
		return OpenVPNCredential{}, err
	}
	return c.OpenVPNCredential, nil
}
