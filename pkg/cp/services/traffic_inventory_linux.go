// SPDX-License-Identifier: Apache-2.0
//go:build linux

package services

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type trafficProcess struct {
	pid, parent, fd int
	owned           bool
	orphanWorker    bool
}

// stopPriorTraffic snapshots process identities before signalling. Ownership is
// a rendered config path, an inherited owner tag, or descent from an owned
// master. pidfds prevent PID reuse from redirecting a signal to a foreign task.
func stopPriorTraffic(ctx context.Context, base, name string) error {
	processes, err := inventoryTraffic(base, name)
	if err != nil {
		return err
	}
	defer closeTrafficInventory(processes)
	var owned []int
	for _, p := range processes {
		if p.owned {
			owned = append(owned, p.fd)
		}
	}
	if len(owned) == 0 {
		return ctx.Err()
	}
	if err := signalTraffic(owned, unix.SIGTERM); err != nil {
		return err
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	killed := false
	for {
		allDone := true
		for _, fd := range owned {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 0); err != nil {
				return err
			}
			allDone = allDone && poll[0].Revents&unix.POLLIN != 0
		}
		if allDone {
			// Catch a child created while its master was being stopped. Never infer
			// absence merely from the master's exit or a stale in-memory child handle.
			remaining, err := inventoryTraffic(base, name)
			if err != nil {
				return err
			}
			defer closeTrafficInventory(remaining)
			for _, p := range remaining {
				if p.owned {
					return errors.New("traffic runtime still present after stop")
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if killed {
				return errors.New("traffic process stop not confirmed")
			}
			killed = true
			if err := signalTraffic(owned, unix.SIGKILL); err != nil {
				return err
			}
			timer.Reset(2 * time.Second)
		case <-tick.C:
		}
	}
}

func signalTraffic(fds []int, signal unix.Signal) error {
	for _, fd := range fds {
		if err := unix.PidfdSendSignal(fd, signal, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	return nil
}

func closeTrafficInventory(processes []trafficProcess) {
	for _, p := range processes {
		_ = unix.Close(p.fd)
	}
}

func inventoryTraffic(base, name string) (result []trafficProcess, err error) {
	defer func() {
		if err != nil {
			closeTrafficInventory(result)
		}
	}()
	paths := trafficConfigPaths(base, name)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid == os.Getpid() {
			continue
		}
		fd, e := unix.PidfdOpen(pid, 0)
		if errors.Is(e, unix.ESRCH) {
			continue
		}
		if e != nil {
			return result, errors.New("traffic process inventory unavailable")
		}
		p := trafficProcess{pid: pid, fd: fd}
		result = append(result, p)
		root := filepath.Join("/proc", entry.Name())
		data, e := os.ReadFile(filepath.Join(root, "cmdline"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return result, errors.New("traffic process inventory unreadable")
		}
		args := bytes.Split(data, []byte{0})
		for i, arg := range args {
			if i == 0 || (string(args[i-1]) != "-c" && string(args[i-1]) != "--config") {
				continue
			}
			for _, path := range paths {
				abs, e := filepath.Abs(path)
				if e != nil {
					return result, e
				}
				p.owned = p.owned || string(arg) == abs
			}
		}
		title := strings.TrimRight(string(data), "\x00")
		if strings.HasPrefix(title, "nginx: master process ") {
			for _, path := range paths {
				p.owned = p.owned || strings.Contains(title, " -c "+path+" -g daemon off;")
			}
		}
		// The marker survives Nginx's rewritten argv and master exit. It is never
		// emitted in diagnostics, and no other environment contents leave this scope.
		if env, e := os.ReadFile(filepath.Join(root, "environ")); e == nil {
			for _, v := range bytes.Split(env, []byte{0}) {
				p.owned = p.owned || string(v) == trafficOwnerTag(base, name)
			}
		}
		stat, e := os.ReadFile(filepath.Join(root, "stat"))
		if e == nil {
			end := strings.LastIndexByte(string(stat), ')')
			if end >= 0 {
				fields := strings.Fields(string(stat[end+1:]))
				if len(fields) > 1 {
					p.parent, _ = strconv.Atoi(fields[1])
					if fields[0] == "Z" {
						p.owned = false
					}
				}
			}
		}
		p.orphanWorker = name == "reverse-proxy" && p.parent == 1 && strings.HasPrefix(title, "nginx: worker process")
		result[len(result)-1] = p
	}
	// Include workers even if their changed credentials make environ unreadable.
	for changed := true; changed; {
		changed = false
		for i := range result {
			if result[i].owned {
				continue
			}
			for _, parent := range result {
				if parent.owned && parent.pid == result[i].parent {
					result[i].owned = true
					changed = true
					break
				}
			}
		}
	}
	for _, p := range result {
		if p.orphanWorker && !p.owned {
			return result, errors.New("unidentified orphan proxy worker; teardown not confirmed")
		}
	}
	return result, nil
}
