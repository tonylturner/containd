// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bytes"
	"context"
	"fmt"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// This standard, non-malicious antivirus test file must be detected. A clean
// verdict (including ICAP 204/bypass) is not scan-path proof. Canaries use the
// raw clients, never Scan: no cache, counters, detections or security events.
const avCanaryPayload = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func (m *AVManager) scanCanary(ctx context.Context, cfg config.AVConfig, dir avscan.Direction) error {
	var verdict string
	var err error
	if avMode(cfg) == "clamav" {
		var result ClamdVerdict
		result, err = (&ClamAVClient{Timeout: avTimeout(cfg), Socket: clamdSocket(cfg)}).Scan(ctx, bytes.NewReader([]byte(avCanaryPayload)), int64(len(avCanaryPayload)))
		verdict = result.Verdict
	} else {
		obj := avscan.Object{
			Direction: dir, Body: bytes.NewReader([]byte(avCanaryPayload)), Size: int64(len(avCanaryPayload)),
			RequestHead:  []byte("GET /containd-av-canary.txt HTTP/1.1\r\nHost: canary.invalid\r\n\r\n"),
			ResponseHead: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"),
		}
		if dir == avscan.Upload {
			obj.RequestHead = []byte("POST /containd-av-canary.txt HTTP/1.1\r\nHost: canary.invalid\r\nContent-Type: application/octet-stream\r\n\r\n")
			obj.ResponseHead = nil
		}
		var result ICAPVerdict
		result, err = m.icapClient(cfg).Scan(ctx, firstICAPServer(cfg), obj)
		verdict = result.Verdict
	}
	if err != nil {
		return err
	}
	if verdict != "malware" {
		return fmt.Errorf("%w: EICAR must be reported infected, got %q", errScanProtocol, verdict)
	}
	return nil
}
