// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// ServedManagement is what this process's bound management listeners serve
// beyond their addresses, which config.BoundManagementListeners records.
type ServedManagement struct {
	// CertFile and KeyFile are the files the bound HTTPS listener serves,
	// which a listener fallback or a path saved after boot can make differ
	// from the saved settings; both empty when no HTTPS listener is bound.
	CertFile, KeyFile string
	// TLS is the bound listener's snapshot, never serialized (it contains a key).
	TLS *mgmttls.Loader `json:"-"`
	// LeafPEM is public-only and refreshed in the local runtime record on reload.
	LeafPEM           string `json:"leafPEM,omitempty"`
	RuntimeRecordFile string `json:"-"`
	// HTTPRedirects reports that the bound HTTP listener redirects GET and
	// HEAD requests to the bound HTTPS listener.
	HTTPRedirects bool
	// HTTPLoopback and HTTPSLoopback report that management bound a
	// separate 127.0.0.1 socket on the port of the bound HTTP or HTTPS
	// listener, whose own address does not accept loopback connections.
	HTTPLoopback, HTTPSLoopback bool
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
//
// A bound listener is called on 127.0.0.1 only when management itself
// accepts connections there: its own socket is a wildcard or 127.0.0.1
// address, or management bound a separate 127.0.0.1 socket on its port. A
// port management did not bind on loopback may belong to another process,
// which must never receive a bearer token.
//
// The bound HTTP listener is preferred, unless it redirects to HTTPS; the
// bound HTTPS listener is called otherwise, trusting only the leaf of the
// certificate file it serves. The client refuses redirects, so a bearer
// token never leaves the chosen listener. With neither listener on
// loopback there is nothing to call.
func LoopbackManagementAPI() (string, *http.Client, error) {
	served := currentServedManagement()
	scheme, port, err := loopbackListener(config.BoundManagementListeners(), served)
	if err != nil {
		return "", nil, err
	}
	baseURL := fmt.Sprintf("%s://127.0.0.1:%d", scheme, port)
	if scheme == "https" {
		return baseURL, snapshotCertificateClient(func() (*x509.Certificate, error) {
			if served.TLS != nil {
				leaf, err := served.TLS.PublicLeaf()
				if leaf != nil {
					return leaf, nil // invalid external rotation keeps the served pin
				}
				return nil, err
			}
			if served.RuntimeRecordFile != "" {
				data, err := os.ReadFile(served.RuntimeRecordFile)
				if err != nil {
					return nil, err
				}
				var rec struct{ Served ServedManagement }
				if err := json.Unmarshal(data, &rec); err != nil {
					return nil, err
				}
				if rec.Served.LeafPEM == "" {
					return nil, errors.New("management runtime record has no public TLS leaf")
				}
				return parseLeafCertificate([]byte(rec.Served.LeafPEM))
			}
			if served.LeafPEM != "" {
				return parseLeafCertificate([]byte(served.LeafPEM))
			}
			return readLeafCertificate(served.CertFile)
		}), nil
	}
	return baseURL, &http.Client{
		Timeout:       loopbackAPITimeout,
		CheckRedirect: refuseLoopbackRedirect,
	}, nil
}

// loopbackListener is the scheme and 127.0.0.1 port of the bound listener
// that LoopbackManagementAPI calls.
func loopbackListener(bound config.ManagementListeners, served ServedManagement) (string, int, error) {
	if bound.HTTP.Port() == 0 && bound.HTTPS.Port() == 0 {
		return "", 0, errors.New("no management HTTP or HTTPS listener bound")
	}
	httpPort := loopbackPort(bound.HTTP, served.HTTPLoopback)
	httpsPort := loopbackPort(bound.HTTPS, served.HTTPSLoopback)
	if httpPort != 0 && (!served.HTTPRedirects || httpsPort == 0) {
		return "http", httpPort, nil
	}
	if httpsPort == 0 {
		return "", 0, errors.New("no bound management HTTP or HTTPS listener accepts connections on 127.0.0.1")
	}
	if served.CertFile == "" {
		return "", 0, errors.New("the bound HTTPS listener recorded no certificate")
	}
	return "https", httpsPort, nil
}

// loopbackPort is the port on which management accepts connections to l on
// 127.0.0.1, given whether a separate 127.0.0.1 socket serves its port; 0
// when it does not.
func loopbackPort(l config.ManagementListener, separate bool) int {
	port := l.Port()
	if port == 0 || separate {
		return port
	}
	host, _, err := net.SplitHostPort(l.Addr)
	if err != nil {
		return 0
	}
	if host == "" {
		return port
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsUnspecified() && ip.Unmap() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) {
		return 0
	}
	return port
}

// Do not forward bearer tokens through redirects, even to another port on
// the same hostname or to an HTTP endpoint.
func refuseLoopbackRedirect(*http.Request, []*http.Request) error {
	return errLoopbackRedirect
}

// snapshotCertificateClient pins only the validated public leaf. Keep-alives
// are disabled so every operation checks the current snapshot, with normal
// validity and server-usage verification in addition to the exact leaf pin.
func snapshotCertificateClient(leaf func() (*x509.Certificate, error)) *http.Client {
	return &http.Client{
		Timeout:       loopbackAPITimeout,
		CheckRedirect: refuseLoopbackRedirect,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				cert, err := leaf()
				if err != nil {
					return nil, err
				}
				cfg, err := leafTLSConfig(cert)
				if err != nil {
					return nil, err
				}
				dialer := &tls.Dialer{Config: cfg}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

// leafTLSConfig verifies the certificate's own SAN while dialing loopback:
// an operator certificate need not contain 127.0.0.1.
func leafTLSConfig(leaf *x509.Certificate) (*tls.Config, error) {
	var name string
	if len(leaf.DNSNames) > 0 {
		name = leaf.DNSNames[0]
	} else if len(leaf.IPAddresses) > 0 {
		name = leaf.IPAddresses[0].String()
	} else {
		return nil, errors.New("management TLS certificate has no DNS or IP subject alternative name")
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

// readLeafCertificate accepts a strict certificate chain or a validated bundle.
func readLeafCertificate(certFile string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read management TLS certificate %q: %w", certFile, err)
	}
	return parseLeafCertificate(data)
}

func parseLeafCertificate(data []byte) (*x509.Certificate, error) {
	leaf, err := mgmttls.ParsePublicLeaf(data)
	if err != nil {
		return nil, fmt.Errorf("parse management TLS certificate: %w", err)
	}
	return leaf, nil
}
