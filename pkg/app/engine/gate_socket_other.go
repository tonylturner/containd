// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build !linux

package engineapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

var errGateTransparentUnsupported = fmt.Errorf("transparent gate sockets require Linux: %w", errors.ErrUnsupported)

// gateTransparentListen reports errors.ErrUnsupported: IP_TRANSPARENT needs Linux.
func gateTransparentListen(context.Context, string, string) (net.Listener, error) {
	return nil, errGateTransparentUnsupported
}

// gateTransparentDial reports errors.ErrUnsupported: IP_TRANSPARENT needs Linux.
func gateTransparentDial(context.Context, string, netip.Addr, uint32, netip.AddrPort) (*net.TCPConn, error) {
	return nil, errGateTransparentUnsupported
}

// gateOriginalDst reports errors.ErrUnsupported: SO_ORIGINAL_DST needs Linux.
func gateOriginalDst(*net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errGateTransparentUnsupported
}

// gateFwmarkAccept reports errors.ErrUnsupported: the sysctl needs Linux.
func gateFwmarkAccept() (bool, error) {
	return false, errGateTransparentUnsupported
}
