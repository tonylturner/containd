// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ServedManagement is what this process's bound management listeners serve
// beyond their addresses, which config.BoundManagementListeners records.
type ServedManagement struct {
	// CertFile and KeyFile are the files the bound HTTPS listener serves,
	// which a listener fallback or a path saved after boot can make differ
	// from the saved settings; both empty when no HTTPS listener is bound.
	CertFile, KeyFile string
	// HTTPRedirects reports that the bound HTTP listener redirects GET and
	// HEAD requests to the bound HTTPS listener.
	HTTPRedirects bool
}

var servedManagement atomic.Pointer[ServedManagement]

// SetServedManagement records what this process's bound management
// listeners serve. Management records it with
// config.SetBoundManagementListeners.
func SetServedManagement(s ServedManagement) {
	servedManagement.Store(&s)
}

func currentServedManagement() ServedManagement {
	if s := servedManagement.Load(); s != nil {
		return *s
	}
	return ServedManagement{}
}

// loopbackAPITimeout bounds one in-process management API call, such as a
// commit or a factory reset.
const loopbackAPITimeout = 30 * time.Second

var errLoopbackRedirect = errors.New("management API redirect refused")

// LoopbackManagementAPI is the base URL and client that the in-app console
// and SSH CLI sessions call this process's management API with. They call
// the listeners management has bound, never a destination derived from a
// request or from the saved settings, which bind at the next start.
// Management serves each bound port on 127.0.0.1 too.
//
// The bound HTTP listener is preferred, unless it redirects to HTTPS; the
// bound HTTPS listener is called otherwise, trusting only the leaf of the
// certificate file it serves. The client refuses redirects, so a bearer
// token never leaves the chosen listener. With neither listener bound there
// is nothing to call.
func LoopbackManagementAPI() (string, *http.Client, error) {
	bound := config.BoundManagementListeners()
	served := currentServedManagement()
	httpPort, httpsPort := bound.HTTP.Port(), bound.HTTPS.Port()
	if httpPort != 0 && (!served.HTTPRedirects || httpsPort == 0) {
		return fmt.Sprintf("http://127.0.0.1:%d", httpPort), &http.Client{
			Timeout:       loopbackAPITimeout,
			CheckRedirect: refuseLoopbackRedirect,
		}, nil
	}
	if httpsPort == 0 {
		return "", nil, errors.New("no management HTTP or HTTPS listener bound")
	}
	if served.CertFile == "" {
		return "", nil, errors.New("the bound HTTPS listener recorded no certificate")
	}
	return fmt.Sprintf("https://127.0.0.1:%d", httpsPort), servedCertificateClient(served.CertFile), nil
}

// Do not forward bearer tokens through redirects, even to another port on
// the same hostname or to an HTTP endpoint.
func refuseLoopbackRedirect(*http.Request, []*http.Request) error {
	return errLoopbackRedirect
}

// servedCertificateClient trusts only the first certificate of certFile, not
// the host's system CAs. It reads the file for every connection, so it
// follows a certificate replaced in place, which the HTTPS listener serves
// from its next handshake; keep-alives are off, so every request connects.
// Normal TLS verification (including validity and server usage) remains
// enabled, with an exact leaf pin as an additional constraint even when the
// leaf is itself a CA.
func servedCertificateClient(certFile string) *http.Client {
	return &http.Client{
		Timeout:       loopbackAPITimeout,
		CheckRedirect: refuseLoopbackRedirect,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				cfg, err := pinnedLeafTLSConfig(certFile)
				if err != nil {
					return nil, err
				}
				dialer := &tls.Dialer{Config: cfg}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

// pinnedLeafTLSConfig verifies the certificate's own SAN while dialing
// loopback: an operator certificate need not contain 127.0.0.1.
func pinnedLeafTLSConfig(certFile string) (*tls.Config, error) {
	leaf, err := readLeafCertificate(certFile)
	if err != nil {
		return nil, err
	}
	var name string
	if len(leaf.DNSNames) > 0 {
		name = leaf.DNSNames[0]
	} else if len(leaf.IPAddresses) > 0 {
		name = leaf.IPAddresses[0].String()
	} else {
		return nil, fmt.Errorf("management TLS certificate %q has no DNS or IP subject alternative name", certFile)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: name,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, leaf.Raw) {
				return errors.New("management TLS certificate does not match its certificate file")
			}
			return nil
		},
	}, nil
}

// readLeafCertificate is the first certificate of a PEM file holding only
// certificates.
func readLeafCertificate(certFile string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read management TLS certificate %q: %w", certFile, err)
	}
	var leaf *x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("parse management TLS certificate %q: expected PEM certificate", certFile)
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("parse management TLS certificate %q: expected PEM certificate", certFile)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse management TLS certificate %q: %w", certFile, err)
		}
		if leaf == nil {
			leaf = cert
		}
		data = rest
	}
	if leaf == nil {
		return nil, fmt.Errorf("parse management TLS certificate %q: no certificates", certFile)
	}
	return leaf, nil
}
