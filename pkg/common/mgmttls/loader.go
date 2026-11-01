// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"sync"
)

// Loader owns the listener's last-good immutable identity. Status and in-process
// pins share this loader; only public leaf bytes leave it.
type Loader struct {
	certFile, keyFile string
	mu                sync.Mutex
	pair              *tls.Certificate
	onChange          func()
}

func NewLoader(certFile, keyFile string) *Loader {
	return &Loader{certFile: certFile, keyFile: keyFile}
}

// Reload reports an invalid rotation while retaining the last-good snapshot.
// With no last-good identity the caller must refuse HTTPS.
func (l *Loader) Reload() (*tls.Certificate, error) {
	l.mu.Lock()
	pair, err := ReadPair(l.certFile, l.keyFile)
	var notify func()
	if err == nil {
		if l.pair == nil || !bytes.Equal(l.pair.Certificate[0], pair.Certificate[0]) {
			notify = l.onChange
		}
		l.pair = pair
	}
	current := l.pair
	l.mu.Unlock()
	if notify != nil {
		notify()
	}
	return current, err
}

func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	pair, err := l.Reload()
	if pair != nil {
		return pair, nil
	}
	return nil, err
}

func (l *Loader) PublicLeaf() (*x509.Certificate, error) {
	pair, err := l.Reload()
	if pair == nil {
		return nil, err
	}
	return pair.Leaf, err
}

// LastLeaf does not reload: record publishers use it from a reload notification.
func (l *Loader) LastLeaf() *x509.Certificate {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pair == nil {
		return nil
	}
	return l.pair.Leaf
}

func (l *Loader) OnChange(f func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onChange = f
}
