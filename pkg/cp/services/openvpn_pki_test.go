// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenVPNPKIHelpers(t *testing.T) {
	t.Parallel()

	if ip, ipnet, err := netParseCIDR4("10.10.0.1/24"); err != nil {
		t.Fatalf("netParseCIDR4(valid): %v", err)
	} else if ip.String() != "10.10.0.1" || ipnet.String() != "10.10.0.0/24" {
		t.Fatalf("unexpected IPv4 CIDR parse: ip=%s net=%s", ip, ipnet)
	}
	if _, _, err := netParseCIDR4("2001:db8::1/64"); err == nil {
		t.Fatal("expected IPv6 CIDR rejection")
	}
	if got := netmaskString(net.CIDRMask(24, 32)); got != "255.255.255.0" {
		t.Fatalf("netmaskString = %q", got)
	}
	if got := sanitizeClientName(" PLC_Admin #1 "); got != "plc_admin1" {
		t.Fatalf("sanitizeClientName = %q", got)
	}
	if serial, err := randSerial(); err != nil || serial.Sign() <= 0 {
		t.Fatalf("randSerial = %v, %v", serial, err)
	}
}

func TestOpenVPNPKICreationAndRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caCert, caKey, err := EnsureOpenVPNCA(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatalf("EnsureOpenVPNCA: %v", err)
	}
	if !fileExists(caCert) || !fileExists(caKey) {
		t.Fatalf("expected CA files to exist: %s %s", caCert, caKey)
	}
	cert, key, err := loadCertAndKey(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertAndKey(CA): %v", err)
	}
	if !cert.IsCA || key == nil {
		t.Fatalf("unexpected CA cert/key: cert=%#v key=%v", cert, key)
	}

	serverCert, serverKey, err := EnsureOpenVPNServerCert(filepath.Join(dir, "pki"), caCert, caKey)
	if err != nil {
		t.Fatalf("EnsureOpenVPNServerCert: %v", err)
	}
	server, _, err := loadCertAndKey(serverCert, serverKey)
	if err != nil {
		t.Fatalf("loadCertAndKey(server): %v", err)
	}
	if len(server.ExtKeyUsage) == 0 || server.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected server ExtKeyUsage: %#v", server.ExtKeyUsage)
	}

	clientCert, clientKey, err := EnsureOpenVPNClientCert(filepath.Join(dir, "pki"), caCert, caKey, "Lab User 01")
	if err != nil {
		t.Fatalf("EnsureOpenVPNClientCert: %v", err)
	}
	client, _, err := loadCertAndKey(clientCert, clientKey)
	if err != nil {
		t.Fatalf("loadCertAndKey(client): %v", err)
	}
	if client.Subject.CommonName != "labuser01" && client.Subject.CommonName != "lab_user_01" {
		t.Fatalf("unexpected client common name: %q", client.Subject.CommonName)
	}
	if len(client.ExtKeyUsage) == 0 || client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected client ExtKeyUsage: %#v", client.ExtKeyUsage)
	}

	// Re-ensuring should reuse the existing files.
	if caCert2, caKey2, err := EnsureOpenVPNCA(filepath.Join(dir, "pki")); err != nil || caCert2 != caCert || caKey2 != caKey {
		t.Fatalf("EnsureOpenVPNCA(reuse) = %q %q %v", caCert2, caKey2, err)
	}
}

func TestOpenVPNPEMHelpers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caCert, caKey, err := EnsureOpenVPNCA(dir)
	if err != nil {
		t.Fatalf("EnsureOpenVPNCA: %v", err)
	}
	if _, err := readFirstPEMBlock(caCert, "CERTIFICATE"); err != nil {
		t.Fatalf("readFirstPEMBlock(cert): %v", err)
	}
	if _, err := readFirstPEMBlock(caKey, "EC PRIVATE KEY"); err != nil {
		t.Fatalf("readFirstPEMBlock(key): %v", err)
	}
	if _, err := readFirstPEMBlock(caCert, "EC PRIVATE KEY"); err == nil {
		t.Fatal("expected wrong block type error")
	}

	textPath := filepath.Join(dir, "not-pem.txt")
	if err := os.WriteFile(textPath, []byte("plain text"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := readFirstPEMBlock(textPath, "CERTIFICATE"); err == nil || !strings.Contains(err.Error(), "pem block not found") {
		t.Fatalf("expected pem block error, got %v", err)
	}
}
