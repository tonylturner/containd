// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	dnpdecoder "github.com/tonylturner/containd/pkg/dp/ics/dnp3"
)

type singleByteReader struct{ io.Reader }

func (r singleByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}
func TestDNPCRCAndPartialRead(t *testing.T) {
	body := []byte{0xc0, 0xc0, 1, 60, 1, 6}
	frame := dnpFrame(body, false)
	// The production parser independently validates link and data CRCs.
	parsed, err := dnpdecoder.ParseFrame(frame)
	if err != nil || !parsed.DataCRCValid() {
		t.Fatalf("independent CRC validation: %v", err)
	}
	got, n, err := readDNP(singleByteReader{bytes.NewReader(frame)}, false)
	if err != nil || !bytes.Equal(got, body) || n != len(frame) {
		t.Fatalf("partial read: %x %d %v", got, n, err)
	}
	for i := range frame {
		bad := bytes.Clone(frame)
		bad[i] ^= 1
		if _, _, err := readDNP(bytes.NewReader(bad), false); err == nil {
			t.Fatalf("accepted corrupt byte %d", i)
		}
	}
}
func TestProtocolRoundTrips(t *testing.T) {
	for _, protocol := range []string{"modbus", "dnp3", "iec104"} {
		t.Run(protocol, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
			done := make(chan error, 1)
			go func() {
				s := session{conn: peer, protocol: protocol}
				if err := s.init(true); err != nil {
					done <- err
					return
				}
				for range 70 {
					if _, _, err := s.exchange(true); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			s := session{conn: client, protocol: protocol}
			if err := s.init(false); err != nil {
				t.Fatal(err)
			}
			for range 70 {
				req, rep, err := s.exchange(false)
				if err != nil || req <= 0 || rep <= 0 {
					t.Fatalf("exchange: %d %d %v", req, rep, err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestIECPartialAndFraming(t *testing.T) {
	frame := iFrame(32767, 32767, iecRead)
	got, err := readIEC(singleByteReader{bytes.NewReader(frame)})
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatal(err)
	}
	for _, b := range [][]byte{{0x67, 4, 0, 0, 0, 0}, {0x68, 3, 0, 0, 0}, {0x68, 254}, {0x68, 4, 0}} {
		if _, err := readIEC(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
func TestSequenceRejection(t *testing.T) {
	for _, protocol := range []string{"modbus", "dnp3", "iec104"} {
		t.Run(protocol, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(time.Second))
			_ = b.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { s := session{conn: b, protocol: protocol, tx: 1}; _, _, err := s.exchange(true); done <- err }()
			var request []byte
			switch protocol {
			case "modbus":
				request = []byte{0, 0, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2}
			case "dnp3":
				request = dnpFrame([]byte{0xc0, 0xc0, 1, 60, 1, 6}, false)
			case "iec104":
				request = iFrame(0, 0, iecRead)
			}
			if err := writeMessage(a, request); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("accepted stale sequence")
			}
		})
	}
}
func TestHistogramMergeUnits(t *testing.T) {
	var a, b histogram
	for range 100 {
		a.add(time.Millisecond)
		b.add(2 * time.Millisecond)
	}
	a.merge(b)
	if a.Count != 200 || a.Buckets[695] != 100 || a.Buckets[764] != 100 {
		t.Fatalf("histogram: n=%d bucket695=%d bucket764=%d", a.Count, a.Buckets[695], a.Buckets[764])
	}
}
func TestTimeoutAccounting(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := &session{conn: a, protocol: "modbus"}
	cfg := loadConfig{Timeout: time.Millisecond}
	var c counts
	if transact(s, cfg, &c) || c.Success != 0 || c.Errors != 1 || c.Timeouts != 1 {
		t.Fatalf("counts %+v", c)
	}
}
func TestReadyRequiresApplicationReply(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	s, err := connectSession(loadConfig{Protocol: "modbus", Addr: l.Addr().String(), Timeout: 10 * time.Millisecond})
	if s != nil || err == nil {
		t.Fatal("connect without validated reply counted ready")
	}
	<-done
}

func TestResetAccounting(t *testing.T) {
	var c counts
	c.failure(&net.OpError{Op: "read", Err: syscall.ECONNRESET})
	c.failure(io.ErrUnexpectedEOF)
	if c.Resets != 1 || c.Errors != 2 || c.Timeouts != 0 {
		t.Fatalf("counts %+v", c)
	}
}
