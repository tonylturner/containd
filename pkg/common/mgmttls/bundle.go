// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var publishMu sync.Mutex

// ErrCommitUncertain means rename succeeded but directory durability is unknown.
// The published identity must not be rolled back.
var ErrCommitUncertain = errors.New("TLS bundle commit uncertain")

// ParseBundle requires a certificate chain followed by exactly one matching key.
// Reject ignored PEM blocks and trailing text rather than accepting ambiguity.
func ParseBundle(data []byte) (*tls.Certificate, error) {
	return parseIdentity(data, true)
}

// ParsePublicLeaf accepts a strict public chain or a bundle whose key matches.
// It never returns private key material.
func ParsePublicLeaf(data []byte) (*x509.Certificate, error) {
	pair, err := parseIdentity(data, false)
	if err != nil {
		return nil, err
	}
	return pair.Leaf, nil
}

func parseIdentity(data []byte, requireKey bool) (*tls.Certificate, error) {
	var certs, key []byte
	var leaf *x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("unexpected text in TLS bundle")
		}
		block, rest := pem.Decode(data)
		if block == nil || len(block.Headers) != 0 {
			return nil, errors.New("invalid PEM in TLS bundle")
		}
		consumed := data[:len(data)-len(rest)]
		if bytes.Contains(consumed[len("-----BEGIN "):], []byte("-----BEGIN ")) {
			return nil, errors.New("invalid PEM in TLS bundle")
		}
		switch block.Type {
		case "CERTIFICATE":
			if key != nil {
				return nil, errors.New("certificate after private key")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			if leaf == nil {
				leaf = cert
			}
			certs = append(certs, pem.EncodeToMemory(block)...)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			if key != nil || len(certs) == 0 {
				return nil, errors.New("ambiguous TLS bundle private key")
			}
			key = pem.EncodeToMemory(block)
		default:
			return nil, fmt.Errorf("unexpected TLS bundle block %q", block.Type)
		}
		data = rest
	}
	if key == nil && !requireKey {
		if leaf == nil {
			return nil, errors.New("no certificates")
		}
		return &tls.Certificate{Leaf: leaf}, nil
	}
	pair, err := tls.X509KeyPair(certs, key)
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	return &pair, nil
}

// ReadPair reads a bundle exactly once. External split files are read-only and
// accepted only after validating their bytes together.
func ReadPair(certFile, keyFile string) (*tls.Certificate, error) {
	pair, _, err := loadPair(certFile, keyFile, pairIdentity{}, diskLoaderOps)
	return pair, err
}

func bundleBytes(cert, key []byte) ([]byte, error) {
	data := bytes.Join([][]byte{bytes.TrimSpace(cert), bytes.TrimSpace(key), nil}, []byte{'\n'})
	if _, err := ParseBundle(data); err != nil {
		return nil, err
	}
	return data, nil
}

type tempFile interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}

// Persistence operations are injectable to exercise each failure boundary.
type publishOps struct {
	create  func(string, string) (tempFile, error)
	rename  func(string, string) error
	syncDir func(string) error
}

var diskOps = publishOps{
	create: func(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) },
	rename: os.Rename,
	syncDir: func(dir string) error {
		f, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	},
}

// Publish validates and durably replaces one 0600 bundle. Writers, including
// first-boot initialization, serialize through the same lock.
func Publish(path string, cert, key []byte) error {
	publishMu.Lock()
	defer publishMu.Unlock()
	data, err := bundleBytes(cert, key)
	if err != nil {
		return err
	}
	return publish(path, data, diskOps)
}

func publish(path string, data []byte, ops publishOps) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := ops.create(dir, ".server-*.pem")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ops.rename(f.Name(), path); err != nil {
		return err
	}
	if err := ops.syncDir(dir); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	return nil
}

// EnsureManaged imports valid legacy files only when the bundle is absent.
// Legacy files are never changed. Invalid or missing legacy files are logged
// and replaced by a newly generated identity in the bundle, not in those files.
func EnsureManaged(bundle, legacyCert, legacyKey string, generate func() ([]byte, []byte, error), logf func(string, ...any)) error {
	publishMu.Lock()
	defer publishMu.Unlock()
	if _, err := os.Stat(bundle); err == nil {
		_, err = ReadPair(bundle, bundle)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cert, certErr := os.ReadFile(legacyCert)
	key, keyErr := os.ReadFile(legacyKey)
	data, err := bundleBytes(cert, key)
	if certErr != nil || keyErr != nil || err != nil {
		logf("legacy management TLS pair unavailable or invalid; generating bundle: cert=%v key=%v pair=%v", certErr, keyErr, err)
		cert, key, err = generate()
		if err != nil {
			return err
		}
		data, err = bundleBytes(cert, key)
		if err != nil {
			return err
		}
	}
	return publish(bundle, data, diskOps)
}
