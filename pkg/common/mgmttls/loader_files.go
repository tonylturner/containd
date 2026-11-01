// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type fileIdentity struct {
	info    os.FileInfo
	failure string
}

func (a fileIdentity) equal(b fileIdentity) bool {
	if a.info == nil || b.info == nil {
		return a.info == nil && b.info == nil && a.failure == b.failure
	}
	// SameFile compares device/inode on Unix, including atomic replacements
	// whose size and modification timestamp happen to match the old file.
	return os.SameFile(a.info, b.info) && a.info.Size() == b.info.Size() &&
		a.info.ModTime().Equal(b.info.ModTime())
}

type pairIdentity struct {
	cert, key fileIdentity
}

func (a pairIdentity) equal(b pairIdentity) bool {
	return a.cert.equal(b.cert) && a.key.equal(b.key)
}

type loaderOps struct {
	stat  func(string) (os.FileInfo, error)
	read  func(string) ([]byte, os.FileInfo, error)
	parse func([]byte) (*tls.Certificate, error)
}

var diskLoaderOps = loaderOps{stat: os.Stat, read: readIdentityFile, parse: ParseBundle}

func observePair(certFile, keyFile string, stat func(string) (os.FileInfo, error)) (pairIdentity, error) {
	cert, certErr := stat(certFile)
	identity := pairIdentity{cert: observedFile(cert, certErr)}
	if filepath.Clean(certFile) == filepath.Clean(keyFile) {
		identity.key = identity.cert
		return identity, certErr
	}
	key, keyErr := stat(keyFile)
	identity.key = observedFile(key, keyErr)
	if certErr != nil {
		return identity, certErr
	}
	return identity, keyErr
}

func observedFile(info os.FileInfo, err error) fileIdentity {
	if err != nil {
		return fileIdentity{failure: err.Error()}
	}
	return fileIdentity{info: info}
}

// Capture identity from the opened inode, not from the path probe: a rename
// between stat and open must not associate new bytes with the old inode.
func readIdentityFile(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, before, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, before, err
	}
	if !(fileIdentity{info: before}).equal(fileIdentity{info: after}) {
		return nil, before, errors.New("management TLS file changed while reading")
	}
	return data, before, nil
}

func loadPair(certFile, keyFile string, identity pairIdentity, ops loaderOps) (*tls.Certificate, pairIdentity, error) {
	cert, certInfo, err := ops.read(certFile)
	if certInfo != nil {
		identity.cert = fileIdentity{info: certInfo}
	}
	bundle := filepath.Clean(certFile) == filepath.Clean(keyFile)
	if bundle {
		identity.key = identity.cert
	}
	if err != nil {
		return nil, identity, err
	}
	if bundle {
		pair, err := ops.parse(cert)
		return pair, identity, err
	}
	key, keyInfo, err := ops.read(keyFile)
	if keyInfo != nil {
		identity.key = fileIdentity{info: keyInfo}
	}
	if err != nil {
		return nil, identity, err
	}
	pair, err := ops.parse(bytes.Join([][]byte{bytes.TrimSpace(cert), bytes.TrimSpace(key), nil}, []byte{'\n'}))
	return pair, identity, err
}
