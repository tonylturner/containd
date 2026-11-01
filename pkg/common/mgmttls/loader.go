// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"
)

// Loader owns the listener's last-good immutable identity. Status and in-process
// pins share this loader; only public leaf bytes leave it.
type Loader struct {
	certFile, keyFile string
	ops               loaderOps
	snapshot          atomic.Pointer[loaderSnapshot]
	reloadMu          sync.Mutex
	callbackMu        sync.Mutex
	onChange          func()
}

type loaderSnapshot struct {
	identity pairIdentity
	pair     *tls.Certificate
	err      error
}

func NewLoader(certFile, keyFile string) *Loader {
	return &Loader{certFile: certFile, keyFile: keyFile, ops: diskLoaderOps}
}

// Reload checks file metadata before reading or parsing. Both accepted and
// rejected identities are cached. An initialized listener never waits for
// another request's reload I/O: it keeps serving its last-good snapshot.
func (l *Loader) Reload() (*tls.Certificate, error) {
	identity, statErr := observePair(l.certFile, l.keyFile, l.ops.stat)
	previous := l.snapshot.Load()
	if previous != nil && previous.identity.equal(identity) {
		return previous.pair, previous.err
	}
	if !l.reloadMu.TryLock() {
		if previous != nil {
			return previous.pair, previous.err
		}
		// Startup loads the first identity before binding HTTPS. Only callers
		// with no initial snapshot need to wait for that first load.
		l.reloadMu.Lock()
		current := l.snapshot.Load()
		l.reloadMu.Unlock()
		return current.pair, current.err
	}
	current := l.snapshot.Load()
	if current != previous {
		// Another reload may have finished after our metadata probe.
		identity, statErr = observePair(l.certFile, l.keyFile, l.ops.stat)
		if current != nil && current.identity.equal(identity) {
			l.reloadMu.Unlock()
			return current.pair, current.err
		}
	}
	next := &loaderSnapshot{identity: identity, err: statErr}
	if current != nil {
		next.pair = current.pair
	}
	var pair *tls.Certificate
	err := statErr
	if err == nil {
		pair, next.identity, err = loadPair(l.certFile, l.keyFile, identity, l.ops)
		next.err = err
	}
	changed := false
	if err == nil {
		changed = next.pair == nil || !bytes.Equal(next.pair.Certificate[0], pair.Certificate[0])
		next.pair = pair
	}
	l.snapshot.Store(next)
	l.reloadMu.Unlock()
	if changed {
		l.callbackMu.Lock()
		notify := l.onChange
		l.callbackMu.Unlock()
		if notify != nil {
			notify()
		}
	}
	return next.pair, next.err
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
	current := l.snapshot.Load()
	if current == nil || current.pair == nil {
		return nil
	}
	return current.pair.Leaf
}

func (l *Loader) OnChange(f func()) {
	l.callbackMu.Lock()
	defer l.callbackMu.Unlock()
	l.onChange = f
}
