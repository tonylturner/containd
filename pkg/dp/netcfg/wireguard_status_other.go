// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package netcfg

import (
	"context"
	"errors"
	"strings"
)

type WireGuardStatus struct {
	Interface  string                `json:"interface"`
	Present    bool                  `json:"present"`
	PublicKey  string                `json:"publicKey,omitempty"`
	ListenPort int                   `json:"listenPort,omitempty"`
	Peers      []WireGuardPeerStatus `json:"peers,omitempty"`
}

type WireGuardPeerStatus struct {
	PublicKey     string   `json:"publicKey"`
	Endpoint      string   `json:"endpoint,omitempty"`
	LastHandshake string   `json:"lastHandshake,omitempty"`
	RxBytes       uint64   `json:"rxBytes,omitempty"`
	TxBytes       uint64   `json:"txBytes,omitempty"`
	AllowedIPs    []string `json:"allowedIPs,omitempty"`
}

func GetWireGuardStatus(_ context.Context, ifaceName string) (WireGuardStatus, error) {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		ifaceName = "wg0"
	}
	return WireGuardStatus{Interface: ifaceName, Present: false}, errors.New("wireguard status not supported on this platform")
}
