// SPDX-License-Identifier: Apache-2.0
package services

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func renderUnbound(cfg config.DNSConfig) string {
	port := cfg.ListenPort
	if port == 0 {
		port = 53
	}
	var b strings.Builder
	b.WriteString("server:\n")
	b.WriteString("  verbosity: 1\n")
	// Ensure Unbound works as a non-root embedded process in containers:
	// - no chroot
	// - no user switching
	// - no pidfile
	// - no syslog (distroless doesn't include it)
	b.WriteString("  username: \"\"\n")
	b.WriteString("  chroot: \"\"\n")
	b.WriteString("  directory: \"/tmp\"\n")
	b.WriteString("  pidfile: \"\"\n")
	b.WriteString("  use-syslog: no\n")
	b.WriteString("  logfile: \"\"\n")
	// Forward-only by default; avoid requiring root trust anchors in early phases.
	b.WriteString("  auto-trust-anchor-file: \"\"\n")
	b.WriteString(fmt.Sprintf("  interface: 0.0.0.0@%d\n", port))
	b.WriteString("  access-control: 0.0.0.0/0 allow\n")
	if cfg.CacheSizeMB > 0 {
		b.WriteString(fmt.Sprintf("  msg-cache-size: %dm\n", cfg.CacheSizeMB))
		b.WriteString(fmt.Sprintf("  rrset-cache-size: %dm\n", cfg.CacheSizeMB))
	}
	if len(cfg.UpstreamServers) > 0 {
		b.WriteString("\nforward-zone:\n")
		b.WriteString("  name: \".\"\n")
		for _, u := range cfg.UpstreamServers {
			b.WriteString(fmt.Sprintf("  forward-addr: %s\n", u))
		}
	}

	return b.String()
}
