// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package conntrack

import (
	"fmt"
	"strconv"
)

// Entry is a minimal, portable conntrack record representation.
// This is intentionally lossy; it's meant for operator visibility (show sessions/conntrack),
// not for full fidelity export. TCP and UDP tuples carry ports; ICMP and
// ICMPv6 tuples carry the identifier, type and code instead.
type Entry struct {
	Proto         string `json:"proto"`
	State         string `json:"state,omitempty"`
	Src           string `json:"src,omitempty"`
	Dst           string `json:"dst,omitempty"`
	Sport         string `json:"sport,omitempty"`
	Dport         string `json:"dport,omitempty"`
	ICMPID        string `json:"icmpId,omitempty"`
	ICMPType      string `json:"icmpType,omitempty"`
	ICMPCode      string `json:"icmpCode,omitempty"`
	ReplySrc      string `json:"replySrc,omitempty"`
	ReplyDst      string `json:"replyDst,omitempty"`
	ReplySport    string `json:"replySport,omitempty"`
	ReplyDport    string `json:"replyDport,omitempty"`
	ReplyICMPID   string `json:"replyIcmpId,omitempty"`
	ReplyICMPType string `json:"replyIcmpType,omitempty"`
	ReplyICMPCode string `json:"replyIcmpCode,omitempty"`
	Mark          string `json:"mark,omitempty"`
	Assured       bool   `json:"assured,omitempty"`
	TimeoutSecs   int    `json:"timeoutSecs,omitempty"`
	Raw           string `json:"raw,omitempty"`
}

// DeleteRequest identifies the original tuple for a low-level conntrack delete.
// Operator termination uses KillRequest and installs a timed revocation first.
// TCP and UDP set the ports; ICMP and ICMPv6 set the identifier, type and code.
type DeleteRequest struct {
	Proto    string `json:"proto"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Sport    int    `json:"sport,omitempty"`
	Dport    int    `json:"dport,omitempty"`
	ICMPID   int    `json:"icmpId,omitempty"`
	ICMPType int    `json:"icmpType,omitempty"`
	ICMPCode int    `json:"icmpCode,omitempty"`
}

// IsICMP reports whether proto names ICMP or ICMPv6.
func IsICMP(proto string) bool { return proto == "icmp" || proto == "icmpv6" }

// Original returns the request that selects e's original tuple. Its numeric
// fields must be unsigned 16-bit decimals; Validate checks the rest.
func (e Entry) Original() (DeleteRequest, error) {
	req := DeleteRequest{Proto: e.Proto, Src: e.Src, Dst: e.Dst}
	texts, fields := []string{e.Sport, e.Dport}, []*int{&req.Sport, &req.Dport}
	if IsICMP(e.Proto) {
		texts, fields = []string{e.ICMPID, e.ICMPType, e.ICMPCode}, []*int{&req.ICMPID, &req.ICMPType, &req.ICMPCode}
	}
	for i, text := range texts {
		v, err := strconv.ParseUint(text, 10, 16)
		if err != nil {
			return req, fmt.Errorf("conntrack entry %s %s → %s has a malformed tuple", e.Proto, e.Src, e.Dst)
		}
		*fields[i] = int(v)
	}
	return req, nil
}
