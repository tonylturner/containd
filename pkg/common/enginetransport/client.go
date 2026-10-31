// SPDX-License-Identifier: Apache-2.0
package enginetransport

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Target is validated once at startup, then shared by all engine callers.
// Its origin and TLS identity are immutable after construction.
type Target struct {
	base      string
	transport *originTransport
}

func (t *Target) URL() string { return t.base }

// ParseURL validates only the grammar and local/plaintext boundary. HTTPS
// identity validation happens in Resolve, even for an HTTPS loopback target.
func ParseURL(raw string) (*url.URL, error) {
	bad := func() (*url.URL, error) {
		return nil, fmt.Errorf("invalid CONTAIND_ENGINE_URL: require an http(s) origin without credentials, path, query or fragment and a valid numeric port")
	}
	if !strings.Contains(raw, "://") {
		host, _, err := net.SplitHostPort(raw)
		if err != nil || !LocalHost(host) {
			return bad()
		}
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad()
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" || u.Hostname() == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" {
		return bad()
	}
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") || strings.Contains(host, ":") || strings.Contains(host, "%") {
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() {
			return bad()
		}
		if a.Zone() != "" && !validZone(a.Zone()) {
			return bad()
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return bad()
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return bad()
		}
	}
	if u.Scheme == "http" && !LocalHost(host) {
		return nil, fmt.Errorf("CONTAIND_ENGINE_URL requires HTTPS for a non-loopback target")
	}
	return u, nil
}

func validZone(zone string) bool {
	for _, c := range zone {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return zone != ""
}

func Resolve(raw string) (*Target, error) {
	u, err := ParseURL(raw)
	if err != nil {
		return nil, err
	}
	var config *tls.Config
	if u.Scheme == "https" {
		secret, err := Secret()
		if err != nil {
			return nil, err
		}
		identity, err := Derive(secret)
		if err != nil {
			return nil, err
		}
		config = identity.ClientTLS()
	}
	// Do not use environment proxies or mutate http.DefaultTransport. Requests
	// must go directly to this origin, including when callers copy http.Client.
	transport := &http.Transport{
		TLSClientConfig: config, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &Target{base: u.String(), transport: &originTransport{scheme: u.Scheme, host: u.Host, transport: transport}}, nil
}

func (t *Target) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: t.transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("engine redirects are refused")
	}}
}

type originTransport struct {
	scheme, host string
	transport    *http.Transport
}

func (t *originTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != t.scheme || r.URL.Host != t.host || r.URL.User != nil || (r.Host != "" && r.Host != t.host) {
		return nil, fmt.Errorf("engine request origin differs from validated CONTAIND_ENGINE_URL")
	}
	return t.transport.RoundTrip(r)
}

func (t *originTransport) CloseIdleConnections() { t.transport.CloseIdleConnections() }
