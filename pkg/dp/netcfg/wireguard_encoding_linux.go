// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type wireGuardAllowedIPEncoding struct {
	family uint16
	ip     []byte
	mask   uint8
}

type wireGuardPeerEncoding struct {
	key       []byte
	endpoint  []byte
	keepalive uint16
	allowed   []wireGuardAllowedIPEncoding
}

func encodeWireGuardPeers(peers []config.WGPeer) ([]wireGuardPeerEncoding, error) {
	out := make([]wireGuardPeerEncoding, 0, len(peers))
	for _, peer := range peers {
		key, err := decodeKey32(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("wireguard: peer publicKey: %w", err)
		}
		if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
			return nil, fmt.Errorf("wireguard: persistentKeepalive must be in 0..65535")
		}
		encoded := wireGuardPeerEncoding{key: key, keepalive: uint16(peer.PersistentKeepalive)}
		if ep := strings.TrimSpace(peer.Endpoint); ep != "" {
			encoded.endpoint, err = encodeSockaddr(ep)
			if err != nil {
				return nil, fmt.Errorf("wireguard: peer endpoint: %w", err)
			}
		}
		for _, cidr := range peer.AllowedIPs {
			family, ip, mask, ok := parseCIDRForWG(strings.TrimSpace(cidr))
			if !ok {
				return nil, fmt.Errorf("wireguard: allowedIP must be an IPv4 CIDR")
			}
			encoded.allowed = append(encoded.allowed, wireGuardAllowedIPEncoding{family: family, ip: ip, mask: mask})
		}
		out = append(out, encoded)
	}
	return out, nil
}
