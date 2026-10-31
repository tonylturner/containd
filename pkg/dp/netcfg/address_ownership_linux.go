// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// One engine per network namespace; serialize both API and background applies.
// No ownership is inferred from intent, subnet, or EEXIST.
var addressApplyMu sync.Mutex

type ownedAddress struct {
	Device string `json:"device"`
	Index  int    `json:"index"`
	MAC    string `json:"mac"`
	CIDR   string `json:"cidr"`
}

type addressOwnership struct {
	Version   int            `json:"version"`
	BootID    string         `json:"bootId"`
	Namespace uint64         `json:"namespace"`
	Addresses []ownedAddress `json:"addresses"`
	path      string
}

func loadAddressOwnership() (*addressOwnership, error) {
	path := strings.TrimSpace(os.Getenv("CONTAIND_ADDRESS_STATE_PATH"))
	if path == "" {
		path = "/data/interface-addresses.json"
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	var ns unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &ns); err != nil {
		return nil, err
	}
	s := &addressOwnership{Version: 1, BootID: strings.TrimSpace(string(boot)), Namespace: ns.Ino, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read address ownership: %w", err)
	}
	var saved addressOwnership
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("decode address ownership: %w", err)
	}
	if saved.Version != s.Version {
		return nil, fmt.Errorf("unsupported address ownership version %d", saved.Version)
	}
	if saved.BootID != s.BootID || saved.Namespace != s.Namespace {
		return s, nil
	}
	for _, a := range saved.Addresses {
		ip, err := parseAddressCIDR(a.CIDR)
		if err != nil || ip == nil || ip.String() != a.CIDR || a.Device == "" || a.Index <= 0 {
			return nil, fmt.Errorf("invalid owned address %+v", a)
		}
	}
	s.Addresses = saved.Addresses
	return s, nil
}

func (s *addressOwnership) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".interface-addresses-*")
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

func addressKey(nic *net.Interface, cidr string) ownedAddress {
	return ownedAddress{Device: nic.Name, Index: nic.Index, MAC: nic.HardwareAddr.String(), CIDR: cidr}
}

func (s *addressOwnership) owns(nic *net.Interface, cidr string) bool {
	key := addressKey(nic, cidr)
	for _, a := range s.Addresses {
		if a == key {
			return true
		}
	}
	return false
}

func (s *addressOwnership) forget(key ownedAddress) error {
	for i, a := range s.Addresses {
		if a == key {
			s.Addresses = append(s.Addresses[:i], s.Addresses[i+1:]...)
			return s.save()
		}
	}
	return nil
}

func (s *addressOwnership) add(nic *net.Interface, ipnet *net.IPNet) error {
	if err := createAddr(nic.Index, ipnet); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return err
	}
	// Record only after a successful exclusive creation. A crash before durable
	// save leaks an unowned address, never claims a foreign one.
	if !s.owns(nic, ipnet.String()) {
		s.Addresses = append(s.Addresses, addressKey(nic, ipnet.String()))
	}
	return s.save()
}
