// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tonylturner/containd/pkg/common/trust"
)

// avTrust is the additional CA bundle the AV clients verify servers with.
type avTrust struct {
	bundle trust.Bundle
	pool   *x509.CertPool // nil: system roots only
}

func (m *AVManager) caBundlePath() string {
	return filepath.Join(m.opts.StateDir, "ca-bundle.pem")
}

// SetTrust makes b the additional CA bundle for ICAP over TLS and FreshClam.
// ICAP scans and probes use it from their next connection; FreshClam from
// its next run. FreshClam receives an engine-local file holding the system
// roots plus b, because CURL_CA_BUNDLE replaces its default roots.
func (m *AVManager) SetTrust(ctx context.Context, b trust.Bundle) error {
	if err := b.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrAVInvalid, err)
	}
	pool, err := b.RootPool()
	if err != nil {
		return err
	}
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.unlock()
	if b.Empty() {
		if err := os.Remove(m.caBundlePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		data, err := b.EffectivePEM()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(m.opts.StateDir, 0o755); err != nil {
			return err
		}
		// FreshClam reads the bundle after dropping to its own account.
		if err := writeFileAtomic(m.caBundlePath(), data, 0o644); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.trust = avTrust{bundle: b, pool: pool}
	m.mu.Unlock()
	m.emit("service.av.trust_applied", map[string]any{"revision": b.Revision})
	return nil
}

// TrustRevision returns the revision of the applied additional CA bundle.
func (m *AVManager) TrustRevision() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return trustRevision(m.trust.bundle)
}

func trustRevision(b trust.Bundle) string {
	if b.Revision == "" {
		return trust.NoRevision
	}
	return b.Revision
}

func (m *AVManager) trustPool() *x509.CertPool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.trust.pool
}

// freshclamEnv is FreshClam's environment. CURL_CA_BUNDLE is set for the
// child only, never process-wide.
func (m *AVManager) freshclamEnv() []string {
	env := os.Environ()
	m.mu.Lock()
	extra := !m.trust.bundle.Empty()
	m.mu.Unlock()
	if extra {
		env = append(env, "CURL_CA_BUNDLE="+m.caBundlePath())
	}
	return env
}
