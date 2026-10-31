// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func netParseCIDR4(s string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return nil, nil, err
	}
	if ip == nil || ip.To4() == nil || ipnet == nil || ipnet.IP.To4() == nil {
		return nil, nil, errors.New("not an IPv4 CIDR")
	}
	return ip.To4(), &net.IPNet{IP: ipnet.IP.To4(), Mask: ipnet.Mask}, nil
}

func netmaskString(m net.IPMask) string {
	if len(m) != 4 {
		return ""
	}
	return net.IPv4(m[0], m[1], m[2], m[3]).String()
}

// EnsureOpenVPNCA ensures a local OpenVPN CA exists under pkiDir and returns cert/key paths.
func EnsureOpenVPNCA(pkiDir string) (certPath, keyPath string, err error) {
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	return ensureOpenVPNCA(pkiDir)
}
func ensureOpenVPNCA(pkiDir string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(pkiDir, "ca.crt")
	keyPath = filepath.Join(pkiDir, "ca.key")
	if fileExists(certPath) || fileExists(keyPath) {
		if _, _, err := loadCertAndKey(certPath, keyPath); err != nil {
			return "", "", err
		}
		return certPath, keyPath, nil
	}
	entries, err := os.ReadDir(pkiDir)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	if len(entries) != 0 {
		return "", "", errors.New("existing PKI has no CA; refusing replacement")
	}
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return "", "", err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := randSerial()
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "containd-openvpn-ca",
			Organization: []string{"containd"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	if err := atomicWritePEMCert(certPath, der); err != nil {
		return "", "", err
	}
	if err := atomicWritePEMECDSAKey(keyPath, key); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// EnsureOpenVPNServerCert ensures a local OpenVPN server certificate exists under pkiDir.
func EnsureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath string) (certPath, keyPath string, err error) {
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	return ensureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath)
}
func ensureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(pkiDir, "server.crt")
	keyPath = filepath.Join(pkiDir, "server.key")
	if fileExists(certPath) || fileExists(keyPath) {
		cert, _, err := loadCertAndKey(certPath, keyPath)
		if err != nil {
			return "", "", err
		}
		ca, _, err := loadCertAndKey(caCertPath, caKeyPath)
		if err != nil {
			return "", "", err
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			return "", "", err
		}
		return certPath, keyPath, nil
	}
	caCert, caKey, err := loadCertAndKey(caCertPath, caKeyPath)
	if err != nil {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := randSerial()
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "containd-openvpn-server",
			Organization: []string{"containd"},
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	if err := atomicWritePEMCert(certPath, der); err != nil {
		return "", "", err
	}
	if err := atomicWritePEMECDSAKey(keyPath, key); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// EnsureOpenVPNClientCert ensures a local OpenVPN client certificate exists under pkiDir.
func EnsureOpenVPNClientCert(pkiDir, caCertPath, caKeyPath, name string) (certPath, keyPath string, err error) {
	openVPNAuthorityMu.Lock()
	defer openVPNAuthorityMu.Unlock()
	if caCertPath != filepath.Join(pkiDir, "ca.crt") || caKeyPath != filepath.Join(pkiDir, "ca.key") {
		return "", "", errors.New("issuer paths do not belong to inventory")
	}
	inv, err := openOpenVPNInventory(pkiDir)
	if err != nil {
		return "", "", err
	}
	credential, err := inv.issue(name)
	if err != nil {
		return "", "", err
	}
	c, err := inv.find(credential.ID)
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(pkiDir, "clients")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	certPath, keyPath = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := atomicWriteFile(certPath, []byte(c.Certificate), 0o600); err != nil {
		return "", "", err
	}
	if err := atomicWriteFile(keyPath, []byte(c.PrivateKey), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func sanitizeClientName(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			// drop
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func loadCertAndKey(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certDER, err := readFirstPEMBlock(certPath, "CERTIFICATE")
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := readFirstPEMBlock(keyPath, "EC PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("certificate/key mismatch")
	}
	return cert, key, nil
}

func readFirstPEMBlock(path, blockType string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var p *pem.Block
		p, b = pem.Decode(b)
		if p == nil {
			return nil, errors.New("pem block not found: " + blockType)
		}
		if p.Type == blockType {
			return p.Bytes, nil
		}
	}
}

func atomicWritePEMCert(path string, der []byte) error {
	return atomicWriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}

func atomicWritePEMECDSAKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
