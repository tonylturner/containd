// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const hostKeyCheckInterval = time.Minute

type hostKeyClock struct {
	now       func() time.Time
	newTicker func(time.Duration) (<-chan time.Time, func())
}

func realHostKeyClock() hostKeyClock {
	return hostKeyClock{
		now: time.Now,
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			ticker := time.NewTicker(d)
			return ticker.C, ticker.Stop
		},
	}
}

func ensureHostKey(path string, rotationDays int) (ssh.Signer, error) {
	return ensureHostKeyAt(path, rotationDays, time.Now())
}

func ensureHostKeyAt(path string, rotationDays int, now time.Time) (ssh.Signer, error) {
	if rotationDays < 0 || rotationDays > config.MaxSSHHostKeyRotationDays {
		return nil, fmt.Errorf("SSH host key rotation days must be in 0..%d", config.MaxSSHHostKeyRotationDays)
	}
	b, err := os.ReadFile(path)
	if err == nil {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if rotationDays == 0 || now.Before(info.ModTime().Add(time.Duration(rotationDays)*24*time.Hour)) {
			return ssh.ParsePrivateKey(b)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return writeHostKey(path, now)
}

// Replace the file only after the complete private key is safely written.
// A failed rotation leaves both the active signer and the previous file intact.
func writeHostKey(path string, now time.Time) (ssh.Signer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := ssh.ParsePrivateKey(p)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".host-key-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("SSH temporary host key cleanup failed", "error", err)
		}
	}()
	defer f.Close()
	if _, err := f.Write(p); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Chtimes(f.Name(), now, now); err != nil {
		return nil, err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return nil, err
	}
	return signer, nil
}

func (s *Server) rotationDays(ctx context.Context) (int, error) {
	if s.opts.HostKeyRotationDaysFunc != nil {
		return s.opts.HostKeyRotationDaysFunc(ctx)
	}
	return s.opts.HostKeyRotationDays, nil
}

// The base is immutable and has no host keys. Each published config owns its
// signer slice; handshakes never race an AddHostKey mutation.
func configWithHostKey(base *ssh.ServerConfig, signer ssh.Signer) *ssh.ServerConfig {
	next := *base
	next.AddHostKey(signer)
	return &next
}

func (s *Server) rotateHostKeys(ctx context.Context, base *ssh.ServerConfig, current *atomic.Pointer[ssh.ServerConfig]) {
	ticks, stop := s.hostKeyClock.newTicker(hostKeyCheckInterval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			days, err := s.rotationDays(ctx)
			if err == nil {
				var signer ssh.Signer
				signer, err = ensureHostKeyAt(s.opts.HostKeyPath, days, s.hostKeyClock.now())
				if err == nil {
					current.Store(configWithHostKey(base, signer))
				}
			}
			if err != nil {
				s.logger.Errorf("SSH host key rotation check failed: %v", err)
			}
		}
	}
}
