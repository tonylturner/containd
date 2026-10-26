// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cp/audit"
)

// Outside lab mode, every refused login check writes an ssh.login denied
// record naming the account and client address, never the secret tried. Each
// refusal also counts against the client's login limit, and attempts the
// limit blocks are refused before any check and write nothing, so one client
// address writes at most the limit's attempts per block period for an account.

// refuseLogin counts a failed check against the client's limit, records it
// outside lab mode and returns err for the client.
func (s *Server) refuseLogin(conn ssh.ConnMetadata, detail string, err error) error {
	s.pwLimiter.Fail(limiterKey(conn.RemoteAddr(), conn.User()))
	if !s.opts.LabMode {
		s.auditLogin(conn, "denied", detail)
	}
	return err
}

// keyRefusals collects the public keys refused on one connection. A client
// offers each key it holds until one is accepted, so a refused key is a
// failed login only when the connection ends without authenticating; it is
// then recorded and counted once per account.
type keyRefusals struct {
	conn     ssh.ConnMetadata
	accounts []string
	byUser   map[string]*keyRefusal
}

type keyRefusal struct {
	reason       string
	fingerprints []string
}

func (r *keyRefusals) add(conn ssh.ConnMetadata, reason string, key ssh.PublicKey) {
	r.conn = conn
	if r.byUser == nil {
		r.byUser = make(map[string]*keyRefusal)
	}
	user := conn.User()
	refusal, ok := r.byUser[user]
	if !ok {
		refusal = &keyRefusal{reason: reason}
		r.byUser[user] = refusal
		r.accounts = append(r.accounts, user)
	}
	refusal.fingerprints = append(refusal.fingerprints, ssh.FingerprintSHA256(key))
}

// recordKeyRefusals runs when a connection ends without authenticating.
func (s *Server) recordKeyRefusals(r *keyRefusals) {
	if s.opts.LabMode || r.conn == nil {
		return
	}
	remote := r.conn.RemoteAddr()
	for _, user := range r.accounts {
		refusal := r.byUser[user]
		s.pwLimiter.Fail(limiterKey(remote, user))
		s.audit(user, audit.Record{
			Action: "ssh.login",
			Target: remote.String(),
			Result: "denied",
			Detail: refusal.reason + ": " + strings.Join(refusal.fingerprints, ", "),
		})
	}
}
