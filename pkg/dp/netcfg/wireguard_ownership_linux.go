// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

var wireGuardApplyMu sync.Mutex

type ownedWireGuardLink struct {
	Index int    `json:"index"`
	Token string `json:"token"`
}

type wireGuardOwnership struct {
	Version   int                  `json:"version"`
	BootID    string               `json:"bootId"`
	Namespace uint64               `json:"namespace"`
	Links     []ownedWireGuardLink `json:"links"`
	path      string
}

func loadWireGuardOwnership() (*wireGuardOwnership, error) {
	path := strings.TrimSpace(os.Getenv("CONTAIND_WIREGUARD_STATE_PATH"))
	if path == "" {
		path = "/data/wireguard-links.json"
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return nil, err
	}
	s := &wireGuardOwnership{Version: 1, BootID: strings.TrimSpace(string(boot)), Namespace: ns.Ino, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read wireguard ownership: %w", err)
	}
	var saved wireGuardOwnership
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("decode wireguard ownership: %w", err)
	}
	if saved.Version != s.Version {
		return nil, fmt.Errorf("unsupported wireguard ownership version %d", saved.Version)
	}
	if saved.BootID != s.BootID || saved.Namespace != s.Namespace {
		return s, nil
	}
	for _, link := range saved.Links {
		if link.Index <= 0 || !strings.HasPrefix(link.Token, "containd-wireguard:") || len(link.Token) != len("containd-wireguard:")+32 {
			return nil, fmt.Errorf("invalid owned wireguard link")
		}
	}
	s.Links = saved.Links
	return s, nil
}

func (s *wireGuardOwnership) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".wireguard-links-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *wireGuardOwnership) ensure(name string) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	token := fmt.Sprintf("containd-wireguard:%x", nonce)
	if err := createWireGuard(name); err != nil {
		if errors.Is(err, unix.EEXIST) {
			// Existing links can satisfy intent, but are never adopted.
			return nil
		}
		return err
	}
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	// RTM_NEWLINK creation does not install IFLA_IFALIAS for WireGuard.
	// Tag only after a successful exclusive create, before durable ownership.
	// A crash before the save leaks an unowned link, never adopts a foreign one.
	if err := setWireGuardAlias(nic.Index, token); err != nil {
		return err
	}
	s.Links = append(s.Links, ownedWireGuardLink{Index: nic.Index, Token: token})
	return s.save()
}

func (s *wireGuardOwnership) cleanup(desired string, remove func(int) error) error {
	links, err := net.Interfaces()
	if err != nil {
		return err
	}
	byIndex := map[int]net.Interface{}
	for _, nic := range links {
		byIndex[nic.Index] = nic
	}
	var failures []error
	keep := make([]ownedWireGuardLink, 0, len(s.Links))
	for _, link := range s.Links {
		nic, present := byIndex[link.Index]
		if !present {
			continue
		}
		alias, err := os.ReadFile(filepath.Join("/sys/class/net", nic.Name, "ifalias"))
		if errors.Is(err, os.ErrNotExist) {
			continue // Removed after the interface snapshot.
		}
		if err != nil {
			keep = append(keep, link)
			failures = append(failures, fmt.Errorf("read wireguard identity %s: %w", nic.Name, err))
			continue
		}
		if strings.TrimSpace(string(alias)) != link.Token {
			continue
		}
		if nic.Name == desired {
			keep = append(keep, link)
			continue
		}
		if err := remove(nic.Index); err != nil && !errors.Is(err, unix.ENODEV) {
			// Retain authority for retry. The kernel token makes a stale
			// record safe even across a crash between delete and save.
			keep = append(keep, link)
			failures = append(failures, fmt.Errorf("delete wireguard link %s: %w", nic.Name, err))
		}
	}
	s.Links = keep
	return errors.Join(append(failures, s.save())...)
}

func setWireGuardAlias(index int, token string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	_ = binary.Write(&req, binary.NativeEndian, unix.NlMsghdr{
		Type: unix.RTM_NEWLINK, Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK, Seq: seq, Pid: uint32(unix.Getpid()),
	})
	_ = binary.Write(&req, binary.NativeEndian, unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: int32(index)})
	addRtAttr(&req, unix.IFLA_IFALIAS, append([]byte(token), 0))
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readAck(fd, seq, false)
}
