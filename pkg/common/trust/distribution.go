// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// NoRevision identifies an empty additional CA bundle.
const NoRevision = "none"

// systemBundleFiles are the Linux CA bundle locations Go also searches.
var systemBundleFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// Bundle is the additional CA bundle content distributed to the processes
// that make outbound TLS connections, with a revision derived from it.
type Bundle struct {
	PEM      string `json:"pem"`
	Revision string `json:"revision"`
}

// Revision returns the deterministic revision of a bundle's PEM text.
func Revision(pemText string) string {
	if pemText == "" {
		return NoRevision
	}
	sum := sha256.Sum256([]byte(pemText))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewBundle validates pemText and returns it with its revision. Empty text
// is the empty bundle.
func NewBundle(pemText []byte) (Bundle, error) {
	text := strings.TrimSpace(string(pemText))
	if text == "" {
		return Bundle{Revision: NoRevision}, nil
	}
	if _, err := Certificates([]byte(text)); err != nil {
		return Bundle{}, err
	}
	text += "\n"
	return Bundle{PEM: text, Revision: Revision(text)}, nil
}

// LoadBundle reads the stored bundle at path. A missing or cleared file is
// the empty bundle.
func LoadBundle(path string) (Bundle, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Bundle{Revision: NoRevision}, nil
	}
	if err != nil {
		return Bundle{}, err
	}
	b, err := NewBundle(data)
	if err != nil {
		return Bundle{}, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// Validate checks that a received bundle parses and matches its revision.
func (b Bundle) Validate() error {
	if b.Revision != Revision(b.PEM) {
		return fmt.Errorf("trusted CA revision %q does not match its content", b.Revision)
	}
	if b.PEM == "" {
		return nil
	}
	_, err := Certificates([]byte(b.PEM))
	return err
}

// Empty reports whether the bundle adds no certificates.
func (b Bundle) Empty() bool { return b.PEM == "" }

// RootPool returns the system roots plus the bundle's certificates, or nil
// (meaning the system roots) for an empty bundle.
func (b Bundle) RootPool() (*x509.CertPool, error) {
	if b.Empty() {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system roots: %w", err)
	}
	if !pool.AppendCertsFromPEM([]byte(b.PEM)) {
		return nil, errors.New("trusted CA bundle has no certificates")
	}
	return pool, nil
}

// SystemBundlePEM returns the system CA bundle file, honouring SSL_CERT_FILE,
// for clients such as FreshClam that take one file replacing their defaults.
func SystemBundlePEM() ([]byte, error) {
	files := systemBundleFiles
	if f := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); f != "" {
		files = []string{f}
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err == nil && len(bytes.TrimSpace(data)) > 0 {
			return data, nil
		}
	}
	return nil, errors.New("no system CA bundle found")
}

// EffectivePEM is the system bundle followed by the additional bundle.
func (b Bundle) EffectivePEM() ([]byte, error) {
	system, err := SystemBundlePEM()
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), bytes.TrimRight(system, "\n")...)
	out = append(out, '\n')
	return append(out, b.PEM...), nil
}
