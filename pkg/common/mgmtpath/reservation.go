// SPDX-License-Identifier: Apache-2.0
package mgmtpath

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// PinPriority is directly after the kernel local-table rule.
const PinPriority = 1

// Reservation is process-owned immutable authority. Consumers must not mutate
// its fields or Sources. It is never accepted from configuration or snapshots.
type Reservation struct {
	Device  string
	Local   netip.Prefix
	Sources []netip.Addr
	Port    uint16
}

type declaration struct {
	subnet  netip.Prefix
	sources []netip.Addr
	listen  string
	port    uint16
}
type nic struct {
	name      string
	up        bool
	addresses []netip.Prefix
}

// Load parses the one canonical environment variable and resolves the live NIC.
func Load() (*Reservation, error) {
	raw := os.Getenv("CONTAIND_MGMT_RESERVATION")
	if raw == "" {
		return nil, nil
	}
	d, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("CONTAIND_MGMT_RESERVATION: %w", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var nics []nic
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		n := nic{name: i.Name, up: true}
		for _, a := range addrs {
			if p, e := netip.ParsePrefix(a.String()); e == nil {
				n.addresses = append(n.addresses, p)
			}
		}
		nics = append(nics, n)
	}
	return resolve(d, nics)
}

func parse(raw string) (declaration, error) {
	var d declaration
	dec := json.NewDecoder(strings.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return d, fmt.Errorf("expected JSON object")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return d, err
		}
		key, ok := token.(string)
		if !ok {
			return d, fmt.Errorf("invalid key")
		}
		if _, ok := fields[key]; ok {
			return d, fmt.Errorf("duplicate field %q", key)
		}
		if key != "subnet" && key != "sources" && key != "listen" {
			return d, fmt.Errorf("unknown field %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return d, err
		}
		if string(value) == "null" {
			return d, fmt.Errorf("%s must not be null", key)
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return d, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return d, fmt.Errorf("trailing JSON")
	}
	var subnet string
	var sources []string
	if err := json.Unmarshal(fields["subnet"], &subnet); err != nil {
		return d, fmt.Errorf("subnet: %w", err)
	}
	d.subnet, err = netip.ParsePrefix(subnet)
	if err != nil || !d.subnet.Addr().Is4() || d.subnet != d.subnet.Masked() {
		return d, fmt.Errorf("subnet must be an IPv4 network prefix")
	}
	if err := json.Unmarshal(fields["sources"], &sources); err != nil {
		return d, fmt.Errorf("sources: %w", err)
	}
	if len(sources) == 0 {
		return d, fmt.Errorf("sources must not be empty")
	}
	seen := map[netip.Addr]bool{}
	for _, s := range sources {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() || !a.IsGlobalUnicast() || !d.subnet.Contains(a) || seen[a] {
			return d, fmt.Errorf("invalid or duplicate source %q", s)
		}
		seen[a] = true
		d.sources = append(d.sources, a)
	}
	if err := json.Unmarshal(fields["listen"], &d.listen); err != nil {
		return d, fmt.Errorf("listen: %w", err)
	}
	host, port, err := net.SplitHostPort(d.listen)
	p, perr := strconv.ParseUint(port, 10, 16)
	if err != nil || perr != nil || p == 0 {
		return d, fmt.Errorf("listen requires an IPv4 bind and numeric TCP port")
	}
	if host != "" && host != "0.0.0.0" {
		a, e := netip.ParseAddr(host)
		if e != nil || !a.Is4() || !d.subnet.Contains(a) {
			return d, fmt.Errorf("listen address must be IPv4 and in subnet")
		}
	}
	d.port = uint16(p)
	return d, nil
}

func resolve(d declaration, nics []nic) (*Reservation, error) {
	r := &Reservation{Sources: d.sources, Port: d.port}
	matches := 0
	for _, n := range nics {
		if n.up {
			for _, p := range n.addresses {
				if p.Addr().Is4() && d.subnet.Contains(p.Addr()) {
					matches++
					r.Device = n.name
					r.Local = p
				}
			}
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("reserved management path: expected one up NIC/address in %s; found %d", d.subnet, matches)
	}
	for _, a := range r.Sources {
		if a == r.Local.Addr() {
			return nil, fmt.Errorf("reserved management path: source equals local address")
		}
	}
	if err := r.ValidateListen(d.listen); err != nil {
		return nil, err
	}
	return r, nil
}

// Admits matches only the socket peer and local endpoint, never forwarded headers.
func (r *Reservation) Admits(remote, local netip.AddrPort) bool {
	return r != nil && remote.IsValid() && local.IsValid() && local.Port() == r.Port && local.Addr().Unmap() == r.Local.Addr() && r.IsSource(remote.Addr().Unmap())
}
func (r *Reservation) IsSource(a netip.Addr) bool {
	if r != nil {
		for _, s := range r.Sources {
			if a == s {
				return true
			}
		}
	}
	return false
}

// ContainsProtected tests a host or prefix against the local address and peers.
func (r *Reservation) ContainsProtected(s string, local bool) bool {
	if r == nil {
		return false
	}
	_, p, e := net.ParseCIDR(strings.TrimSpace(s))
	if e != nil {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return false
		}
		a = a.Unmap()
		p = &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
	}
	if local && p.Contains(net.IP(r.Local.Addr().AsSlice())) {
		return true
	}
	for _, a := range r.Sources {
		if p.Contains(net.IP(a.AsSlice())) {
			return true
		}
	}
	return false
}
func (r *Reservation) ValidateListen(addr string) error {
	if r == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	p, e := strconv.ParseUint(port, 10, 16)
	if err != nil || e != nil || p != uint64(r.Port) || (host != "" && host != "0.0.0.0" && host != r.Local.Addr().String()) {
		return fmt.Errorf("httpListenAddr %q conflicts with reserved management path", addr)
	}
	return nil
}
func (r *Reservation) ValidateEngineBind(addr string) error {
	if r == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	a, ae := netip.ParseAddr(host)
	p, pe := strconv.ParseUint(port, 10, 16)
	if err != nil || ae != nil || !a.IsLoopback() || pe != nil || p == 0 {
		return fmt.Errorf("CONTAIND_ENGINE_ADDR %q must be loopback for reserved management path", addr)
	}
	return nil
}

// DNATOverlaps checks a match, independent of the translated destination and the
// global NAT toggle (port forwards are compiled even when that toggle is false).
func (r *Reservation) DNATOverlaps(enabled bool, proto string, port int, devices, sources []string) bool {
	if r == nil || !enabled || !strings.EqualFold(strings.TrimSpace(proto), "tcp") || port != int(r.Port) {
		return false
	}
	found := false
	for _, d := range devices {
		if d == r.Device {
			found = true
		}
	}
	if !found {
		return false
	}
	if len(sources) == 0 {
		return true
	}
	for _, s := range sources {
		if r.ContainsProtected(s, false) {
			return true
		}
	}
	return false
}
