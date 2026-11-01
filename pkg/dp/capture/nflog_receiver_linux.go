// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Only the nfnetlink_log UAPI used by rule-hit capture is implemented.
const (
	nfLogSubsystem = 4
	nfLogConfig    = 1
	nfLogCmd       = 1
	nfLogMode      = 2
	nfLogFlags     = 6
	nfLogBind      = 1
	nfLogUnbind    = 2
	nfLogPayload   = 9
	nfLogPrefix    = 10
	nfLogCTInfo    = 19
)

type nfLogAttribute struct {
	Prefix  *string
	Payload *[]byte
	CtInfo  *uint32
}

type nfLogConn interface {
	Execute(netlink.Message) ([]netlink.Message, error)
	Receive() ([]netlink.Message, error)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	Close() error
}

// mu serializes Start with Close. done exists before launching the sole
// receive worker, and closes only after all hooks and cleanup have finished.
// Hooks must not call Close themselves.
type nfLogReceiver struct {
	mu     sync.Mutex
	conn   nfLogConn
	group  uint16
	cancel context.CancelFunc
	done   chan struct{}
	closed bool
	err    error
}

var openNFLog = func(group uint16) (nfLogHandle, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	return &nfLogReceiver{conn: conn, group: group}, nil
}

func (r *nfLogReceiver) configure(attrs ...netlink.Attribute) error {
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return err
	}
	header := []byte{unix.AF_UNSPEC, 0, byte(r.group >> 8), byte(r.group)}
	_, err = r.conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(nfLogSubsystem<<8 | nfLogConfig),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(header, data...),
	})
	return err
}

func (r *nfLogReceiver) Start(ctx context.Context, hook func(nfLogAttribute), onError func(error) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.done != nil {
		return errors.New("nflog receiver already started or closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Bound synchronous kernel configuration independently of the caller.
	if err := r.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	// Modern kernels bind groups directly. Do not unbind protocol families:
	// that would interfere with other consumers in the network namespace.
	if err := r.configure(netlink.Attribute{Type: nfLogCmd, Data: []byte{nfLogBind}}); err != nil {
		return fmt.Errorf("bind group %d: %w", r.group, err)
	}
	// struct nfulnl_msg_config_mode: network-order copy_range, copy_mode,
	// and padding. A zero range selects the kernel's maximum packet copy.
	if err := r.configure(
		netlink.Attribute{Type: nfLogMode, Data: []byte{0, 0, 0, 0, 2, 0}},
		netlink.Attribute{Type: nfLogFlags, Data: []byte{0, 4}}, // NFULNL_CFG_F_CONNTRACK
	); err != nil {
		return fmt.Errorf("configure group %d: %w", r.group, err)
	}
	if err := r.conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go r.receive(ctx, hook, onError)
	return nil
}

func (r *nfLogReceiver) receive(ctx context.Context, hook func(nfLogAttribute), onError func(error) bool) {
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		// Interrupt Receive without closing the socket so normal teardown can
		// send the group-unbind acknowledgement before releasing the socket.
		_ = r.conn.SetReadDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		r.cancel()
		if !stopInterrupt() {
			<-interrupted
		}
		// Socket close is also the kernel's authoritative unbind if the
		// socket was lost or the explicit teardown request fails.
		err := r.conn.SetDeadline(time.Now().Add(time.Second))
		if err == nil {
			err = r.configure(netlink.Attribute{Type: nfLogCmd, Data: []byte{nfLogUnbind}})
		}
		r.err = errors.Join(err, r.conn.Close())
		close(r.done)
	}()
	for ctx.Err() == nil {
		msgs, err := r.conn.Receive()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if !onError(err) {
				return
			}
			continue
		}
		for _, msg := range msgs {
			if ctx.Err() != nil {
				return
			}
			if msg.Header.Type != netlink.HeaderType(nfLogSubsystem<<8) {
				continue // e.g. NLMSG_DONE batch terminator
			}
			a, err := parseNFLog(msg.Data, r.group)
			if err != nil {
				continue // malformed individual packet, not source loss
			}
			hook(a)
		}
	}
}

// Close cancels and joins the worker, including any in-progress hook. It is
// safe before Start, immediately after Start, and concurrently with Close.
func (r *nfLogReceiver) Close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		if r.cancel != nil {
			r.cancel()
		} else {
			r.err = r.conn.Close()
		}
	}
	done := r.done
	r.mu.Unlock()
	if done != nil {
		<-done
	}
	return r.err
}

func parseNFLog(data []byte, group uint16) (nfLogAttribute, error) {
	var a nfLogAttribute
	if len(data) < 4 || data[1] != 0 || binary.BigEndian.Uint16(data[2:4]) != group {
		return a, errors.New("invalid nflog header")
	}
	ad, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return a, err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case nfLogPrefix:
			prefix := ad.String()
			a.Prefix = &prefix
		case nfLogPayload:
			payload := ad.Bytes()
			a.Payload = &payload
		case nfLogCTInfo:
			info := ad.Uint32()
			a.CtInfo = &info
		}
	}
	return a, ad.Err()
}
