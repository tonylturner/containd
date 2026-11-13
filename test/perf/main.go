// SPDX-License-Identifier: Apache-2.0
// The endpoint deliberately implements only the fixed read-only workloads.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

func save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(path+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
func marker(path string, deadline time.Time) error {
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("barrier timeout: %s", path)
}

type peerState struct {
	mu                                  sync.Mutex
	Established, Ready, Replies, Errors int64
}

func serveConn(c net.Conn, protocol string, st *peerState) {
	defer c.Close()
	st.mu.Lock()
	st.Established++
	st.mu.Unlock()
	ready := false
	defer func() {
		st.mu.Lock()
		st.Established--
		if ready {
			st.Ready--
		}
		st.mu.Unlock()
	}()
	s := session{conn: c, protocol: protocol}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if err := s.init(true); err != nil {
		st.mu.Lock()
		st.Errors++
		st.mu.Unlock()
		return
	}
	for {
		if err := c.SetDeadline(time.Now().Add(150 * time.Second)); err != nil {
			return
		}
		_, _, err := s.exchange(true)
		if err != nil {
			return
		}
		st.mu.Lock()
		if !ready {
			st.Ready++
			ready = true
		}
		st.Replies++
		st.mu.Unlock()
	}
}
func peer(dir string) error {
	st := &peerState{}
	for protocol, port := range ports {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return err
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go serveConn(c, protocol, st)
			}
		}()
	}
	control, err := net.Listen("tcp", ":25000")
	if err != nil {
		return err
	}
	defer control.Close()
	go func() {
		for {
			c, err := control.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	for {
		st.mu.Lock()
		snapshot := map[string]int64{"established": st.Established, "ready": st.Ready, "replies": st.Replies, "errors": st.Errors}
		st.mu.Unlock()
		if err := save(filepath.Join(dir, "peer.json"), snapshot); err != nil {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}
func main() {
	mode := flag.String("mode", "load", "peer, load, or connect")
	protocol := flag.String("protocol", "modbus", "modbus, dnp3, iec104")
	addr := flag.String("addr", "", "destination host:port")
	n := flag.Int("sessions", 1, "main application-ready sessions (probe is separate)")
	rate := flag.Float64("rate", 100, "total scheduled main transactions/second")
	warm := flag.Duration("warmup", 10*time.Second, "warmup before barrier")
	measure := flag.Duration("measure", 60*time.Second, "steady hold")
	timeout := flag.Duration("timeout", 2*time.Second, "transaction timeout")
	dir := flag.String("dir", "/results", "barrier and JSON directory")
	flag.Parse()
	var err error
	switch *mode {
	case "version":
		err = json.NewEncoder(os.Stdout).Encode(map[string]string{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	case "peer":
		err = peer(*dir)
	case "connect":
		var c net.Conn
		c, err = net.DialTimeout("tcp", *addr, *timeout)
		if err == nil {
			c.Close()
		}
	case "load":
		if ports[*protocol] == 0 || *n < 1 || *n > 2048 || *rate <= 0 || *rate > 100000 || *measure <= 0 || *warm < 0 || *timeout <= 0 {
			err = fmt.Errorf("invalid load arguments")
			break
		}
		err = load(loadConfig{Protocol: *protocol, Addr: *addr, Sessions: *n, Rate: *rate, Warmup: *warm, Measure: *measure, Timeout: *timeout, Dir: *dir})
	default:
		err = fmt.Errorf("invalid mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
