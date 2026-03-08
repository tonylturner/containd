// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"fmt"

	nfqueue "github.com/florianl/go-nfqueue/v2"
)

// nfqueueSource captures packets via NFQUEUE and delivers them to a Handler.
type nfqueueSource struct {
	queueID int
	cfg     Config
	handler Handler
}

func (m *Manager) startNFQueue(ctx context.Context, handler Handler) error {
	src := &nfqueueSource{
		queueID: m.cfg.QueueID,
		cfg:     m.cfg,
		handler: handler,
	}
	go func() {
		if err := src.run(ctx); err != nil {
			if m.cfg.OnError != nil {
				m.cfg.OnError(err)
			}
		}
	}()
	return nil
}

func (s *nfqueueSource) run(ctx context.Context) error {
	cfg := nfqueue.Config{
		NfQueue:      uint16(s.queueID),
		MaxPacketLen: uint32(s.cfg.Snaplen),
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("nfqueue open queue %d: %w", s.queueID, err)
	}

	// Close the nfqueue handle when the context is done.
	go func() {
		<-ctx.Done()
		_ = nf.Close()
	}()

	hookFn := func(a nfqueue.Attribute) int {
		if a.Payload == nil || len(*a.Payload) == 0 {
			if a.PacketID != nil {
				_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			}
			return 0
		}
		pkt, ok := decodeIPPacket(*a.Payload)
		if !ok {
			// Not a parseable IP packet -- accept and move on.
			if a.PacketID != nil {
				_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
			}
			return 0
		}

		// Deliver to capture handler (DPI/telemetry).
		s.handler(pkt)

		// Default verdict is ACCEPT. The verdict cache in the engine will
		// override this via nftables set updates for blocked flows.
		if a.PacketID != nil {
			_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		return 0
	}

	errFn := func(e error) int {
		if s.cfg.OnError != nil {
			s.cfg.OnError(e)
		}
		if ctx.Err() != nil {
			return 1
		}
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, hookFn, errFn); err != nil {
		_ = nf.Close()
		return fmt.Errorf("nfqueue register: %w", err)
	}

	// Block until context is cancelled.
	<-ctx.Done()
	return nil
}
