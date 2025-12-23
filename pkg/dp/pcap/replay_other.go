//go:build !linux

package pcap

import (
	"context"
	"errors"
	"net"
)

func replayFile(ctx context.Context, path string, iface *net.Interface, ratePPS int) error {
	return errors.New("pcap replay is only supported on linux")
}
