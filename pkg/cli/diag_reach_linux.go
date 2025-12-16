//go:build linux

package cli

import (
	"strings"
	"syscall"
)

func bindToDeviceControl(dev string) func(network, address string, c syscall.RawConn) error {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		if err := c.Control(func(fd uintptr) {
			// Bind the socket to a specific interface to validate path/egress.
			ctrlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}

