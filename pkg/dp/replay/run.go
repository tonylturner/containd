// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

const (
	MinGap       = 100 * time.Millisecond
	MaxGap       = 5 * time.Second
	CapturePause = 10 * time.Second
)

// Processor must finish HandlePacket promptly. Run calls it synchronously:
// there is no helper goroutine to outlive cancellation or a joined Run.
type Processor interface{ HandlePacket(capture.Packet) }

// Status is a copy of replay progress, obtained through Counters.Status.
type Status struct {
	Loops   uint64
	Capture string
}

// PacedGap clamps recorded gaps, including equal/backward timestamps. Waiting
// is relative to the previous injection, never a catch-up burst.
func PacedGap(recorded time.Duration) time.Duration {
	return min(MaxGap, max(MinGap, recorded))
}

// Run replays in manifest order until ctx ends. Use a fresh processor per run,
// not per loop, to preserve its protocol-counter epoch. Cancellation returns
// ctx.Err and all packet handling/counter charging has finished on return.
func Run(ctx context.Context, set *CaptureSet, topo Topology, p Processor, c *Counters) error {
	if set == nil || len(set.Captures) == 0 || p == nil || c == nil {
		return fmt.Errorf("replay requires captures, processor and counters")
	}
	if err := c.start(set, topo); err != nil {
		return err
	}
	defer c.stop()
	for loop := uint64(0); ; loop++ {
		for i := range set.Captures {
			cap := &set.Captures[i]
			c.progress(loop, cap.File)
			for j, rec := range cap.records {
				if j > 0 {
					if err := wait(ctx, PacedGap(rec.packet.Timestamp.Sub(cap.records[j-1].packet.Timestamp))); err != nil {
						return err
					}
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				pkt, from, to, err := topo.rewrite(cap, rec.packet, loop)
				if err != nil {
					return fmt.Errorf("%s: %w", cap.File, err)
				}
				pkt.Timestamp = time.Now()
				// Protect verified payloads even if a processor mutates input.
				pkt.Payload = append([]byte(nil), pkt.Payload...)
				p.HandlePacket(pkt)
				c.charge(from, to, uint64(rec.origLen), uint64(rec.ipLen))
			}
			if i == len(set.Captures)-1 {
				c.progress(loop+1, cap.File)
			}
			if err := wait(ctx, CapturePause); err != nil {
				return err
			}
		}
	}
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
