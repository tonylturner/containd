// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package pcap

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type worker struct {
	dir   string
	iface string
	cfg   config.PCAPConfig
	index int
	files []string
}

func newWorker(dir, iface string, cfg config.PCAPConfig) *worker {
	return &worker{dir: dir, iface: iface, cfg: cfg}
}

func (w *worker) run(ctx context.Context, mgr *Manager) error {
	iface, err := net.InterfaceByName(w.iface)
	if err != nil {
		return fmt.Errorf("unknown interface %q: %w", w.iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons16(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		return err
	}
	if w.cfg.BufferMB > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, w.cfg.BufferMB*1024*1024)
	}
	if w.cfg.Promisc {
		_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		})
	}

	fwds := buildForwarders(w.iface, w.cfg)
	defer func() {
		for _, f := range fwds {
			f.Close()
		}
	}()

	pc, err := w.openFile()
	if err != nil {
		return err
	}
	defer pc.close()

	buf := make([]byte, w.cfg.Snaplen)
	rotateAt := w.nextRotate()

	for {
		if ctx.Err() != nil {
			return nil
		}
		if w.shouldRotate(pc, rotateAt) {
			if w.cfg.Mode == "once" {
				mgr.requestStop()
				return nil
			}
			pc.close()
			pc, err = w.openFile()
			if err != nil {
				return err
			}
			rotateAt = w.nextRotate()
		}
		timeout := 250
		pollfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollfds, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 || pollfds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		rn, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return err
		}
		if rn <= 0 {
			continue
		}
		data := buf[:rn]
		if w.cfg.Snaplen > 0 && rn > w.cfg.Snaplen {
			data = data[:w.cfg.Snaplen]
		}
		if !matchFilter(data, w.cfg.Filter) {
			continue
		}
		if err := pc.writePacket(time.Now(), data); err != nil {
			return err
		}
		for _, f := range fwds {
			_ = f.WritePacket(time.Now(), data)
		}
	}
}

func (w *worker) openFile() (*pcapFile, error) {
	ts := time.Now().UTC().Format("20060102_150405")
	base := fmt.Sprintf("%s_%s_%d.pcap", sanitizePrefix(w.cfg.FilePrefix), w.iface, w.index)
	if !strings.Contains(base, ts) {
		base = fmt.Sprintf("%s_%s_%s_%d.pcap", sanitizePrefix(w.cfg.FilePrefix), w.iface, ts, w.index)
	}
	w.index++
	path := filepath.Join(w.dir, base)
	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := writePCAPGlobalHeader(f, uint32(w.cfg.Snaplen)); err != nil {
		_ = f.Close()
		return nil, err
	}
	meta := Meta{
		Name:      base,
		Interface: w.iface,
		CreatedAt: time.Now().UTC(),
		Tags:      []string{},
		Status:    "ready",
	}
	_ = writeMeta(metaPath(path), meta)
	w.files = append(w.files, path)
	if w.cfg.Mode == "rolling" && w.cfg.MaxFiles > 0 && len(w.files) > w.cfg.MaxFiles {
		old := w.files[0]
		w.files = w.files[1:]
		_ = os.Remove(old)
		_ = os.Remove(metaPath(old))
	}
	return &pcapFile{
		path:      path,
		file:      f,
		snaplen:   uint32(w.cfg.Snaplen),
		createdAt: time.Now().UTC(),
	}, nil
}

func (w *worker) shouldRotate(pc *pcapFile, rotateAt time.Time) bool {
	if w.cfg.RotateSeconds > 0 && time.Now().After(rotateAt) {
		return true
	}
	if w.cfg.MaxSizeMB > 0 && pc.sizeBytes >= int64(w.cfg.MaxSizeMB)*1024*1024 {
		return true
	}
	return false
}

func (w *worker) nextRotate() time.Time {
	if w.cfg.RotateSeconds <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(w.cfg.RotateSeconds) * time.Second)
}

func sanitizePrefix(v string) string {
	if v == "" {
		return "capture"
	}
	out := strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, v)
	return strings.Trim(out, "_")
}

type pcapFile struct {
	path      string
	file      *os.File
	snaplen   uint32
	sizeBytes int64
	createdAt time.Time
}

func (p *pcapFile) writePacket(ts time.Time, data []byte) error {
	if int(p.snaplen) < len(data) {
		data = data[:p.snaplen]
	}
	if err := writePCAPPacket(p.file, ts, data); err != nil {
		return err
	}
	p.sizeBytes += int64(len(data) + 16)
	return nil
}

func (p *pcapFile) close() {
	if p.file != nil {
		_ = p.file.Close()
	}
}

type forwardSink struct {
	iface string
	cfg   config.PCAPForwardTarget
	conn  net.Conn
	sent  bool
}

func buildForwarders(iface string, cfg config.PCAPConfig) []*forwardSink {
	var out []*forwardSink
	for _, t := range cfg.ForwardTargets {
		if !t.Enabled || t.Interface != iface {
			continue
		}
		if t.Host == "" || t.Port == 0 {
			continue
		}
		target := net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
		network := "udp"
		if strings.ToLower(t.Proto) == "tcp" {
			network = "tcp"
		}
		conn, err := net.DialTimeout(network, target, 2*time.Second)
		if err != nil {
			continue
		}
		out = append(out, &forwardSink{iface: iface, cfg: t, conn: conn})
	}
	return out
}

func (f *forwardSink) WritePacket(ts time.Time, data []byte) error {
	if f.conn == nil {
		return nil
	}
	if !f.sent {
		if err := writePCAPGlobalHeader(f.conn, 65535); err != nil {
			return err
		}
		f.sent = true
	}
	return writePCAPPacket(f.conn, ts, data)
}

func (f *forwardSink) Close() {
	if f.conn != nil {
		_ = f.conn.Close()
	}
}

func htons16(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
