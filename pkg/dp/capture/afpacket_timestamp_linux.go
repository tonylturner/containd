// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package capture

import (
	"encoding/binary"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sys/unix"
)

// SO_TIMESTAMPNS uses the native timespec ABI, including on 32-bit Linux.
var afPacketTimespecSize = binary.Size(unix.Timespec{})

// The default Prometheus registry exports this counter from the engine's
// metrics endpoint. Only packets delivered with a userspace fallback count.
var afPacketTimestampFallbacks = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "containd",
	Subsystem: "dp",
	Name:      "afpacket_timestamp_fallbacks_total",
	Help:      "AF_PACKET packets delivered with userspace time because the kernel receive timestamp was missing or invalid.",
})

func afPacketReceiveTime(oob []byte, flags int) time.Time {
	if ts, ok := afPacketKernelTimestamp(oob, flags); ok {
		return ts
	}
	afPacketTimestampFallbacks.Inc()
	return time.Now().UTC()
}

// afPacketKernelTimestamp rejects incomplete ancillary data rather than using
// a partial timespec or mistaking another socket option's payload for one.
func afPacketKernelTimestamp(oob []byte, flags int) (time.Time, bool) {
	if flags&unix.MSG_CTRUNC != 0 {
		return time.Time{}, false
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}, false
	}
	for _, msg := range msgs {
		if msg.Header.Level != unix.SOL_SOCKET || msg.Header.Type != unix.SO_TIMESTAMPNS {
			continue
		}
		var ts unix.Timespec
		if len(msg.Data) != afPacketTimespecSize {
			return time.Time{}, false
		}
		if _, err := binary.Decode(msg.Data, binary.NativeEndian, &ts); err != nil {
			return time.Time{}, false
		}
		if ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 {
			return time.Time{}, false
		}
		return time.Unix(int64(ts.Sec), int64(ts.Nsec)).UTC(), true
	}
	return time.Time{}, false
}
