// SPDX-License-Identifier: Apache-2.0

// Package trust validates and persists the appliance's additional CA bundle.
package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const DefaultBundlePath = "/data/tls/trusted_ca.pem"

// Certificates strictly parses a nonempty bundle containing only CA certificates.
func Certificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("expected a PEM CERTIFICATE block")
		}
		const endMarker = "-----END CERTIFICATE-----"
		end := bytes.Index(data, []byte(endMarker))
		if end < 0 {
			return nil, errors.New("unterminated PEM certificate")
		}
		end += len(endMarker)
		if bytes.Count(data[:end], []byte("-----BEGIN ")) != 1 {
			return nil, errors.New("nested or malformed PEM certificate")
		}
		block, rest := pem.Decode(data[:end])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("malformed PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid X.509 certificate: %w", err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, errors.New("certificate must have CA basic constraints")
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("CA certificate does not permit certificate signing")
		}
		certs = append(certs, cert)
		data = data[end:]
	}
	if len(certs) == 0 {
		return nil, errors.New("CA bundle is empty; use clear to remove additional trust")
	}
	return certs, nil
}

// WriteBundle replaces a validated bundle atomically. Empty data clears it.
// Readers see either the complete old bundle or the complete new bundle.
func WriteBundle(path string, data []byte) error {
	if len(data) > 0 {
		if _, err := Certificates(data); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".trusted-ca-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
