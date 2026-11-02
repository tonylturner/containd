// SPDX-License-Identifier: Apache-2.0

// Package replay feeds verified recorded traffic to a caller-owned, detached
// packet processor. It has no network or enforcement capabilities.
package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

const DefaultCaptureDir = "/usr/share/containd/demo"

// Role is an endpoint's recorded identity, independent of packet direction.
type Role struct {
	Role            string `json:"role"`
	OriginalAddress string `json:"originalAddress"`
	host            byte
}

// Capture describes one immutable recording and its provenance.
type Capture struct {
	File    string `json:"file"`
	Family  string `json:"family"`
	SHA256  string `json:"sha256"`
	License string `json:"license"`
	Mutated bool   `json:"mutated"`
	Roles   []Role `json:"roles"`
	records []record
	ports   map[uint16]uint64
}

type record struct {
	packet  capture.Packet
	origLen int
	ipLen   int
}

// CaptureSet is verified in its entirety before it can be replayed.
// Its recordings are private and immutable after loading.
type CaptureSet struct {
	Version  int       `json:"version"`
	Captures []Capture `json:"captures"`
}

// LoadCaptureSet reads manifest.json and every named recording below dir.
// No partial set is returned on failure. Verification and decoding happen
// before Run, so replay never observes a file changed after verification.
func LoadCaptureSet(dir string) (*CaptureSet, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	var set CaptureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	if set.Version != 1 || len(set.Captures) == 0 {
		return nil, fmt.Errorf("manifest.json: unsupported version or empty capture set")
	}
	seen := make(map[string]bool)
	// Each recording gets distinct endpoint identities. The first client and
	// server use .10/.20; additional endpoints use .21+ in manifest order.
	nextHost := 21
	first := map[string]bool{}
	for i := range set.Captures {
		c := &set.Captures[i]
		if !filepath.IsLocal(c.File) || seen[c.File] {
			return nil, fmt.Errorf("%s: nonlocal or duplicate capture path", c.File)
		}
		seen[c.File] = true
		if err := c.validateRoles(first, &nextHost); err != nil {
			return nil, fmt.Errorf("%s: %w", c.File, err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, c.File))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.File, err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != c.SHA256 {
			return nil, fmt.Errorf("%s: sha256 mismatch", c.File)
		}
		if err := c.decode(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", c.File, err)
		}
	}
	return &set, nil
}

func (c *Capture) validateRoles(first map[string]bool, next *int) error {
	switch c.Family {
	case "modbus", "dnp3", "iec104", "cip", "it":
	default:
		return fmt.Errorf("unknown family %q", c.Family)
	}
	if c.License != "Apache-2.0" {
		return fmt.Errorf("unsupported fixture license %q", c.License)
	}
	addresses, kinds := map[string]bool{}, map[string]bool{}
	for i := range c.Roles {
		r := &c.Roles[i]
		ip := net.ParseIP(r.OriginalAddress)
		if ip == nil || ip.To4() == nil || addresses[r.OriginalAddress] || (r.Role != "client" && r.Role != "server") {
			return fmt.Errorf("invalid or duplicate endpoint role %+v", *r)
		}
		addresses[r.OriginalAddress], kinds[r.Role] = true, true
		if !first[r.Role] {
			r.host = 10
			if r.Role == "server" {
				r.host = 20
			}
			first[r.Role] = true
		} else {
			if *next > 254 {
				return fmt.Errorf("too many endpoints for demo /24 address plan")
			}
			r.host = byte(*next)
			*next++
		}
	}
	if !kinds["client"] || !kinds["server"] {
		return fmt.Errorf("client and server roles required")
	}
	return nil
}

func (c *Capture) decode(raw []byte) error {
	reader, err := pcap.OpenReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	c.ports = map[uint16]uint64{}
	for {
		ts, data, origLen, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		pkt, ok := capture.DecodeEthernetFrame(data)
		if !ok || pkt.IPVersion != 4 || !pkt.PortsValid {
			return fmt.Errorf("frame %d: unsupported Ethernet/IP packet", len(c.records)+1)
		}
		if c.role(pkt.SrcIP) == nil || c.role(pkt.DstIP) == nil {
			return fmt.Errorf("frame %d: endpoint missing from roles", len(c.records)+1)
		}
		clientPort := pkt.SrcPort
		if c.role(pkt.SrcIP).Role == "server" {
			clientPort = pkt.DstPort
		}
		if _, exists := c.ports[clientPort]; !exists {
			if len(c.ports) == 41000 {
				return fmt.Errorf("too many client ports for demo ephemeral range")
			}
			c.ports[clientPort] = uint64(len(c.ports))
		}
		pkt.Timestamp = ts
		// The verified corpus is Ethernet IPv4; account for VLAN headers too.
		linkLen := 14
		for data[linkLen-2] == 0x81 && data[linkLen-1] == 0 || data[linkLen-2] == 0x88 && data[linkLen-1] == 0xa8 {
			linkLen += 4
		}
		c.records = append(c.records, record{pkt, origLen, max(0, origLen-linkLen)})
	}
	if len(c.records) == 0 {
		return fmt.Errorf("empty recording")
	}
	return nil
}

func (c *Capture) role(ip net.IP) *Role {
	for i := range c.Roles {
		if ip.Equal(net.ParseIP(c.Roles[i].OriginalAddress)) {
			return &c.Roles[i]
		}
	}
	return nil
}
