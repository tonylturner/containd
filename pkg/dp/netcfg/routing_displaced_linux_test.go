// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestDisplacedRoutesJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine", "routing-displaced.json")
	t.Setenv("CONTAIND_ROUTING_STATE_PATH", path)
	state, err := loadDisplacedRoutes()
	if err != nil {
		t.Fatal(err)
	}
	raw := buildAddRouteRequest(1, &net.IPNet{IP: net.IPv4zero}, 0, unix.RT_TABLE_MAIN, 42, net.ParseIP("198.19.0.2").To4(), 0)[unix.NLMSG_HDRLEN:]
	(*unix.RtMsg)(unsafe.Pointer(&raw[0])).Protocol = unix.RTPROT_BOOT
	route, ok := decodeKernelRoute(raw)
	if !ok {
		t.Fatal("fixture did not decode")
	}
	if err := state.remember(route); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadDisplacedRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Routes) != 1 || !bytes.Equal(raw, loaded.Routes[0]) {
		t.Fatal("journal did not retain exact route payload")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("journal permissions: %v", stat.Mode())
	}
	// A repeated displacement must not replace the original saved next hop.
	changed := route
	changed.gateway = net.ParseIP("198.19.0.3")
	if err := loaded.remember(changed); err == nil {
		t.Fatal("silently discarded an earlier displaced route")
	}
	loaded.Namespace = state.Namespace ^ 1
	if err := loaded.save(); err != nil {
		t.Fatal(err)
	}
	fresh, err := loadDisplacedRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Routes) != 0 {
		t.Fatal("replayed a foreign network namespace's journal")
	}
	loaded.Namespace = state.Namespace
	loaded.BootID = "different-" + state.BootID
	if err := loaded.save(); err != nil {
		t.Fatal(err)
	}
	fresh, err = loadDisplacedRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Routes) != 0 {
		t.Fatal("replayed a previous boot's journal")
	}
}

func TestDisplacedRoutesInvalidStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	t.Setenv("CONTAIND_ROUTING_STATE_PATH", path)
	state, err := loadDisplacedRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"{", fmt.Sprintf(`{"version":%d}`, state.Version^1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadDisplacedRoutes(); err == nil {
			t.Fatalf("accepted invalid journal %q", data)
		}
	}
	// Persistence must fail before replacement when the directory is unwritable
	// as a directory, including when running this test as root.
	t.Setenv("CONTAIND_ROUTING_STATE_PATH", filepath.Join(path, "state.json"))
	if _, err := loadDisplacedRoutes(); err == nil {
		t.Fatal("accepted a non-directory state path")
	}
}
