// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"net"
	"strconv"
)

// udpForwarder is a small UDP forwarder helper used for syslog delivery.
type udpForwarder struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

func newUDPForwarder(address string, port int) (*udpForwarder, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	return &udpForwarder{addr: udpAddr, conn: conn}, nil
}

func (u *udpForwarder) forward(msg []byte) error {
	if u.conn == nil {
		return net.ErrClosed
	}
	_, err := u.conn.Write(msg)
	return err
}

func (u *udpForwarder) close() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}
