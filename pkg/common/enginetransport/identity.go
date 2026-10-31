// SPDX-License-Identifier: Apache-2.0

// Package enginetransport owns the engine's namespace-local HTTP and
// secret-derived mutual TLS transport. Every secret holder is both peers.
package enginetransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

const ServerName = "containd-engine"

// LocalHost deliberately does not resolve names, including localhost.
// Scoped addresses are remote, even if a zone was added to a loopback IP.
func LocalHost(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.Zone() == "" && a.Unmap().IsLoopback()
}

func Secret() ([]byte, error) {
	return ParseSecret(strings.TrimSpace(os.Getenv("CONTAIND_ENGINE_SECRET")))
}

func ParseSecret(s string) ([]byte, error) {
	const message = "CONTAIND_ENGINE_SECRET must be 64 hex characters encoding 32 random bytes (generate with openssl rand -hex 32)"
	if len(s) != 64 {
		return nil, fmt.Errorf("%s", message)
	}
	b, err := hex.DecodeString(s)
	if err != nil || bytes.Equal(b, bytes.Repeat(b[:1], len(b))) {
		return nil, fmt.Errorf("%s", message)
	}
	return b, nil
}

type Identity struct {
	Server tls.Certificate
	Client tls.Certificate
}

// Derive uses a fixed certificate template so independent processes and the
// credential exporter produce identical trust anchors. Rotation, not expiry,
// revokes these identities; their validity deliberately spans 2020 through 9999.
func Derive(secret []byte) (*Identity, error) {
	server, err := certificate(secret, "server", ServerName, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	client, err := certificate(secret, "client", "containd-engine-client", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	return &Identity{Server: server, Client: client}, nil
}

func certificate(secret []byte, role, name string, usage x509.ExtKeyUsage) (tls.Certificate, error) {
	seed, err := hkdf.Key(sha256.New, secret, []byte("containd-engine-transport-v1"), role+"-key", ed25519.SeedSize)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := hkdf.Key(sha256.New, secret, []byte("containd-engine-transport-v1"), role+"-serial", 16)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial[0] |= 1 // positive and nonzero, including for an all-zero KDF output
	key := ed25519.NewKeyFromSeed(seed)
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	if role == "server" {
		template.DNSNames = []string{ServerName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func (i *Identity) ServerTLS() *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(i.Client.Leaf)
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{i.Server},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
}

func (i *Identity) ClientTLS() *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(i.Server.Leaf)
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{i.Client},
		RootCAs: roots, ServerName: ServerName}
}

// ListenerTLS validates before callers create engine resources or bind sockets.
// A malformed, unused secret must not change the namespace-local HTTP path.
func ListenerTLS(addr string) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid CONTAIND_ENGINE_ADDR")
	}
	if LocalHost(host) {
		return nil, nil
	}
	secret, err := Secret()
	if err != nil {
		return nil, err
	}
	identity, err := Derive(secret)
	if err != nil {
		return nil, err
	}
	return identity.ServerTLS(), nil
}
