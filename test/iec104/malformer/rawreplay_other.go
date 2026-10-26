//go:build !linux

package main

import "fmt"

// staleRetransmit needs raw IPv4 sockets and is Linux-only. On other platforms
// it reports the limitation; the harness only ever runs it inside the Linux
// control-centre container.
func staleRetransmit(o options) result {
	return result{name: o.scenario, fatal: fmt.Errorf("stale-retransmit requires linux (raw sockets)")}
}
