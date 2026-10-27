// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The journal is written before replacing a foreign route. Namespace identity
// prevents a persisted record from being replayed into a newly created netns.
// Each network namespace must have a single engine and its own state path.
type displacedRoutes struct {
	Version   int      `json:"version"`
	BootID    string   `json:"bootId"`
	Namespace uint64   `json:"namespace"`
	Routes    [][]byte `json:"routes"`
	path      string
}

func loadDisplacedRoutes() (*displacedRoutes, error) {
	path := strings.TrimSpace(os.Getenv("CONTAIND_ROUTING_STATE_PATH"))
	if path == "" {
		path = "/data/routing-displaced.json"
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err != nil {
		return nil, err
	}
	state := &displacedRoutes{Version: 1, BootID: strings.TrimSpace(string(boot)), Namespace: st.Ino, path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read displaced routes %s: %w", path, err)
	}
	var saved displacedRoutes
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("decode displaced routes %s: %w", path, err)
	}
	if saved.Version != state.Version {
		return nil, fmt.Errorf("unsupported displaced routes version %d", saved.Version)
	}
	if saved.BootID != state.BootID || saved.Namespace != state.Namespace {
		return state, nil
	}
	for _, raw := range saved.Routes {
		r, ok := decodeKernelRoute(raw)
		if !ok || !restorableRoute(r) || r.proto == routeProtoContaind {
			return nil, fmt.Errorf("invalid displaced route in %s", path)
		}
	}
	state.Routes = saved.Routes
	return state, nil
}

func (s *displacedRoutes) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".routing-displaced-*")
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
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *displacedRoutes) remember(r kernelRoute) error {
	for _, raw := range s.Routes {
		original, _ := decodeKernelRoute(raw)
		if sameRouteKey(original, r) {
			if original.proto != r.proto || !routeMatchesIntent(r, original) || !bytes.Equal(original.raw, r.raw) {
				return fmt.Errorf("foreign %s changed while a displaced route is recorded", routeDescription(r))
			}
			return nil
		}
	}
	s.Routes = append(s.Routes, r.raw)
	return s.save()
}

func (s *displacedRoutes) restoreRemoved(ctx context.Context, intent []kernelRoute) error {
	for i := 0; i < len(s.Routes); {
		original, _ := decodeKernelRoute(s.Routes[i])
		retained := false
		for _, want := range intent {
			if sameRouteKey(original, want) {
				retained = true
				break
			}
		}
		if retained {
			i++
			continue
		}
		routes, err := kernelRoutes(ctx)
		if err != nil {
			return err
		}
		present := false
		for _, r := range routes {
			if !sameRouteKey(r, original) {
				continue
			}
			if r.proto != original.proto || !routeMatchesIntent(r, original) || !bytes.Equal(r.raw, original.raw) {
				return fmt.Errorf("restore displaced %s: conflicting route is now present", routeDescription(original))
			}
			present = true
		}
		if !present {
			if err := restoreRoute(s.Routes[i]); err != nil {
				return fmt.Errorf("restore displaced %s: %w", routeDescription(original), err)
			}
		}
		s.Routes = append(s.Routes[:i], s.Routes[i+1:]...)
		if err := s.save(); err != nil {
			return err
		}
	}
	return nil
}

func sameRouteKey(a, b kernelRoute) bool {
	return a.dst.Equal(b.dst) && a.dstLen == b.dstLen && a.table == b.table && a.tos == b.tos && a.metric == b.metric
}

func routeDescription(r kernelRoute) string {
	return fmt.Sprintf("route %s/%d table %d tos %d metric %d via %s oif %d", r.dst, r.dstLen, r.table, r.tos, r.metric, r.gateway, r.ifIndex)
}

// Reject routes whose next-hop shape cannot be represented by our simple
// static-route intent. Preserve the complete original payload when restoring,
// including its protocol, scope, preferred source, metrics and on-link flag.
func restorableRoute(r kernelRoute) bool {
	if len(r.raw) < unix.SizeofRtMsg {
		return false
	}
	rm := (*unix.RtMsg)(unsafe.Pointer(&r.raw[0]))
	if rm.Type != unix.RTN_UNICAST || rm.Src_len != 0 || (rm.Scope != unix.RT_SCOPE_UNIVERSE && rm.Scope != unix.RT_SCOPE_LINK) || rm.Flags & ^uint32(unix.RTNH_F_ONLINK) != 0 {
		return false
	}
	for _, a := range parseNetlinkAttrs(r.raw[unix.SizeofRtMsg:]) {
		switch a.Type {
		case unix.RTA_DST, unix.RTA_GATEWAY, unix.RTA_OIF, unix.RTA_PRIORITY, unix.RTA_PREFSRC, unix.RTA_METRICS, unix.RTA_TABLE:
		default:
			return false
		}
	}
	return true
}

func restoreRoute(raw []byte) error {
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	seq := atomic.AddUint32(&nlSeq, 1)
	var request bytes.Buffer
	_ = binary.Write(&request, binary.NativeEndian, unix.NlMsghdr{Len: uint32(unix.NLMSG_HDRLEN + len(raw)), Type: unix.RTM_NEWROUTE, Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL, Seq: seq, Pid: uint32(unix.Getpid())})
	request.Write(raw)
	if err := unix.Sendto(fd, request.Bytes(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readRoutingAck(fd, seq)
}
