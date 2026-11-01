// SPDX-License-Identifier: Apache-2.0
//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	ctaMark     = 8
	ctaID       = 12
	ctaZone     = 18
	ctaMarkMask = 21
)

func nlAttrU32(typ uint16, value uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	return nlAttr(typ, b)
}

// ClearMark clears clearMask on entries with mark&matchMask == matchValue.
// The dump is filtered by the kernel and checked again locally. Updates use
// CTA_MARK_MASK, not a userspace read/modify/write of unrelated bits. Entries
// expiring between dump and update are harmless. The count is acknowledged
// updates; a partial sweep returns both its count and an error.
//
// A mark changing after the dump can still be cleared. Callers must serialize
// admission-epoch reuse with sweep completion; this is not an atomic filter
// and update operation.
func ClearMark(ctx context.Context, matchMask, matchValue, clearMask uint32) (int, error) {
	if matchValue&^matchMask != 0 || clearMask == 0 {
		return 0, fmt.Errorf("conntrack mark: invalid match value or empty clear mask")
	}
	payload := append([]byte{unix.AF_UNSPEC, 0, 0, 0}, nlAttrU32(ctaMark, matchValue)...)
	payload = append(payload, nlAttrU32(ctaMarkMask, matchMask)...)
	// Finish the dump before updating: updates must not interrupt the dump,
	// and dump callback records alias a reusable receive buffer.
	var updates [][]byte
	err := exchange(ctx, 0x101, payload, true, func(record []byte) (bool, error) {
		update, err := markClearRequest(record, matchMask, matchValue, clearMask)
		if update != nil {
			updates = append(updates, update)
		}
		return false, err
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, update := range updates {
		err := exchange(ctx, 0x100, update, false, nil)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func markClearRequest(record []byte, matchMask, matchValue, clearMask uint32) ([]byte, error) {
	if len(record) < 4 {
		return nil, fmt.Errorf("short conntrack mark record")
	}
	a, err := attributes(record[4:])
	if err != nil {
		return nil, err
	}
	var mark uint32
	if v := a[ctaMark]; len(v) != 0 {
		if len(v) != 4 {
			return nil, fmt.Errorf("invalid conntrack mark length")
		}
		mark = binary.BigEndian.Uint32(v)
	}
	if mark&matchMask != matchValue || mark&clearMask == 0 {
		return nil, nil
	}
	if len(a[1]) == 0 || len(a[ctaID]) != 4 {
		return nil, fmt.Errorf("conntrack mark record lacks tuple or identity")
	}
	out := append([]byte(nil), record[:4]...)
	out = append(out, nlAttr(1|0x8000, a[1])...)
	out = append(out, nlAttr(ctaID, a[ctaID])...)
	if zone := a[ctaZone]; len(zone) != 0 {
		out = append(out, nlAttr(ctaZone, zone)...)
	}
	out = append(out, nlAttrU32(ctaMark, 0)...)
	return append(out, nlAttrU32(ctaMarkMask, clearMask)...), nil
}
