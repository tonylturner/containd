// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/httpgate"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Bounds of the gate that no configuration sets. The AV configuration
// bounds the objects the scanner accepts; these bound what the gate holds
// and how long it waits for peers and the scanner.
const (
	// gateDefaultMaxObjectBytes bounds held bodies when maxSizeBytes is 0
	// (unlimited for the scanner): a body beyond it is Unscanned/oversized
	// and follows the fail policy.
	gateDefaultMaxObjectBytes int64 = 1 << 30
	// gateMemoryThreshold is the largest body held in memory; longer ones
	// spool to disk.
	gateMemoryThreshold      int64 = 4 << 20
	gateMaxConnections             = 1024
	gateMaxConcurrentObjects       = 64
	gateIdleTimeout                = 90 * time.Second
	gateObjectTimeout              = 10 * time.Minute
	gateDialTimeout                = 10 * time.Second
	// gateMinScanTimeout is the least time one scan may take. The backend
	// timeout bounds connecting; a large clean object legitimately takes
	// longer, so the scan deadline is a multiple of it.
	gateMinScanTimeout     = time.Minute
	gateScanTimeoutPerUnit = 10
)

// gateSettings maps the AV configuration and the compiled selection to the
// gate's settings. The AV configuration is the authority for the policy
// the operator chose; the selection contributes the resolved ICS
// endpoints. An absent fail policy is open and an absent download mode
// is hold, as the configuration defines them.
func gateSettings(gate rules.GateSelection, av config.AVConfig) httpgate.Settings {
	backend := time.Duration(av.TimeoutSec) * time.Second
	if backend <= 0 {
		backend = services.DefaultAVTimeout
	}
	maxObject := av.MaxSizeBytes
	if maxObject <= 0 {
		maxObject = gateDefaultMaxObjectBytes
	}
	return httpgate.Settings{
		ScanUploads:          av.HTTPUpload,
		ScanDownloads:        av.HTTPDownload,
		DownloadMode:         httpgate.DownloadMode(av.Scan.EffectiveDownloadMode()),
		MaxObjectBytes:       maxObject,
		FailPolicy:           avscan.FailPolicy(av.EffectiveFailPolicy()),
		ICSBypass:            true,
		IsICS:                gateICSMatcher(gate.ICSCIDRs),
		MemoryThreshold:      min(gateMemoryThreshold, maxObject),
		MaxConnections:       gateMaxConnections,
		MaxConcurrentObjects: gateMaxConcurrentObjects,
		IdleTimeout:          gateIdleTimeout,
		ObjectTimeout:        gateObjectTimeout,
		DialTimeout:          gateDialTimeout,
		ScanTimeout:          max(gateScanTimeoutPerUnit*backend, gateMinScanTimeout),
	}
}

// gateICSMatcher reports whether either endpoint lies in an ICS prefix. It
// is nil when there are none, so nothing is ICS.
func gateICSMatcher(cidrs []string) func(client, server netip.Addr) bool {
	var prefixes []netip.Prefix
	for _, cidr := range cidrs {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	return func(client, server netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(client.Unmap()) || p.Contains(server.Unmap()) {
				return true
			}
		}
		return false
	}
}
