// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type managementRoute struct {
	header   unix.RtMsg
	table    uint32
	dst, src []byte
	index    uint32
	payload  []byte
}

func parseManagementRoute(m syscall.NetlinkMessage) (managementRoute, bool) {
	if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
		return managementRoute{}, false
	}
	h := *(*unix.RtMsg)(unsafe.Pointer(&m.Data[0]))
	if h.Family != unix.AF_INET {
		return managementRoute{}, false
	}
	r := managementRoute{header: h, table: uint32(h.Table), payload: m.Data}
	for _, a := range parseNetlinkAttrs(m.Data[unix.SizeofRtMsg:]) {
		switch a.Type {
		case unix.RTA_DST:
			r.dst = a.Value
		case unix.RTA_PREFSRC:
			r.src = a.Value
		case unix.RTA_OIF:
			if len(a.Value) == 4 {
				r.index = binary.NativeEndian.Uint32(a.Value)
			}
		case unix.RTA_TABLE:
			if len(a.Value) == 4 {
				r.table = binary.NativeEndian.Uint32(a.Value)
			}
		}
	}
	return r, true
}
