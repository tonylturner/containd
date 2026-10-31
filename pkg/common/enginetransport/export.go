// SPDX-License-Identifier: Apache-2.0
package enginetransport

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Export creates operator credentials in an existing directory. Every file is
// exclusive: existing files and symlinks are refused. On failure, callers must
// inspect any partially created files; no existing material is removed.
func Export(dir string) error {
	secret, err := Secret()
	if err != nil {
		return err
	}
	identity, err := Derive(secret)
	if err != nil {
		return err
	}
	key, err := x509.MarshalPKCS8PrivateKey(identity.Client.PrivateKey)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, file := range []struct {
		name, kind string
		data       []byte
		mode       os.FileMode
	}{
		{"server.crt", "CERTIFICATE", identity.Server.Certificate[0], 0644},
		{"client.crt", "CERTIFICATE", identity.Client.Certificate[0], 0644},
		{"client.key", "PRIVATE KEY", key, 0600},
	} {
		f, err := root.OpenFile(file.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.mode)
		if err != nil {
			return fmt.Errorf("export %s: %w", file.name, err)
		}
		writeErr := pem.Encode(f, &pem.Block{Type: file.kind, Bytes: file.data})
		closeErr := f.Close()
		if writeErr != nil {
			return fmt.Errorf("export %s: %w", file.name, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("export %s: %w", file.name, closeErr)
		}
	}
	return nil
}
