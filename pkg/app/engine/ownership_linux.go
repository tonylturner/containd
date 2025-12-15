//go:build linux

package engineapp

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/dp/netcfg"
	"golang.org/x/sys/unix"
)

type ownershipState struct {
	ifaces  []config.Interface
	routing config.RoutingConfig
}

type ownershipManager struct {
	logger *log.Logger

	state atomic.Value // ownershipState
	// reconcile requests are coalesced.
	reconcileCh chan struct{}

	mu sync.Mutex
	// lastApplyErr is best-effort state for troubleshooting.
	lastApplyErr string
}

func newOwnershipManager(logger *log.Logger) *ownershipManager {
	m := &ownershipManager{
		logger:      logger,
		reconcileCh: make(chan struct{}, 1),
	}
	m.state.Store(ownershipState{})
	return m
}

func (m *ownershipManager) setInterfaces(ifaces []config.Interface) {
	st := m.state.Load().(ownershipState)
	st.ifaces = append([]config.Interface(nil), ifaces...)
	m.state.Store(st)
	m.triggerReconcile()
}

func (m *ownershipManager) setRouting(routing config.RoutingConfig) {
	st := m.state.Load().(ownershipState)
	st.routing = routing
	m.state.Store(st)
	m.triggerReconcile()
}

func (m *ownershipManager) currentInterfaces() []config.Interface {
	st := m.state.Load().(ownershipState)
	return append([]config.Interface(nil), st.ifaces...)
}

func (m *ownershipManager) getLastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastApplyErr
}

func (m *ownershipManager) setLastError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		m.lastApplyErr = ""
		return
	}
	m.lastApplyErr = err.Error()
}

func (m *ownershipManager) triggerReconcile() {
	select {
	case m.reconcileCh <- struct{}{}:
	default:
	}
}

func (m *ownershipManager) start(ctx context.Context) {
	go m.reconcileLoop(ctx)
	go m.netlinkWatchLoop(ctx)
}

func (m *ownershipManager) reconcileLoop(ctx context.Context) {
	// Run periodically even without netlink events so drift is corrected.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Debounce bursts of netlink events/config updates.
	var pending bool
	var debounce *time.Timer
	debounceC := (<-chan time.Time)(nil)
	defer func() {
		if debounce != nil {
			debounce.Stop()
		}
	}()

	reconcileNow := func(reason string) {
		st := m.state.Load().(ownershipState)
		if len(st.ifaces) == 0 && len(st.routing.Routes) == 0 && len(st.routing.Rules) == 0 {
			return
		}
		applyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Interfaces: additive, non-destructive apply (REPLACE is admin-triggered only).
		if len(st.ifaces) > 0 {
			if err := netcfg.ApplyInterfaces(applyCtx, st.ifaces); err != nil {
				m.setLastError(err)
				m.logger.Printf("ownership reconcile (%s) apply interfaces failed: %v", reason, err)
				return
			}
		}

		// Routing: additive apply. We resolve logical iface names to kernel devices
		// using the current interface bindings before applying.
		if len(st.routing.Routes) > 0 || len(st.routing.Rules) > 0 {
			resolved := resolveRoutingIfaces(st.routing, st.ifaces)
			if err := netcfg.ApplyRouting(applyCtx, resolved); err != nil {
				m.setLastError(err)
				m.logger.Printf("ownership reconcile (%s) apply routing failed: %v", reason, err)
				return
			}
		}

		m.setLastError(nil)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.reconcileCh:
			pending = true
			if debounce == nil {
				debounce = time.NewTimer(350 * time.Millisecond)
				debounceC = debounce.C
			} else {
				if !debounce.Stop() {
					select {
					case <-debounce.C:
					default:
					}
				}
				debounce.Reset(350 * time.Millisecond)
			}
		case <-debounceC:
			if pending {
				pending = false
				reconcileNow("event")
			}
			debounceC = nil
			debounce = nil
		case <-ticker.C:
			reconcileNow("periodic")
		}
	}
}

func (m *ownershipManager) netlinkWatchLoop(ctx context.Context) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		m.logger.Printf("ownership netlink watch disabled: %v", err)
		return
	}
	defer unix.Close(fd)

	groups := uint32(0)
	// Link state changes.
	groups |= unix.RTNLGRP_LINK
	// IPv4/IPv6 address changes.
	groups |= unix.RTNLGRP_IPV4_IFADDR
	groups |= unix.RTNLGRP_IPV6_IFADDR
	// Route changes (useful for default route drift).
	groups |= unix.RTNLGRP_IPV4_ROUTE
	groups |= unix.RTNLGRP_IPV6_ROUTE

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		m.logger.Printf("ownership netlink watch disabled: %v", err)
		return
	}

	buf := make([]byte, 1<<16)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Block until something changes.
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// If the socket becomes invalid (container constraints), stop watching.
			m.logger.Printf("ownership netlink watch stopped: %v", err)
			return
		}
		if n <= 0 {
			continue
		}
		// We don't need to parse messages to drive the reconcile loop; any relevant
		// kernel network change is a good time to re-assert desired state.
		m.triggerReconcile()
	}
}

func ownershipStatusJSON(m *ownershipManager) []byte {
	if m == nil {
		return []byte(`{"enabled":false}`)
	}
	st := m.state.Load().(ownershipState)
	ifaces := make([]string, 0, len(st.ifaces))
	for _, i := range st.ifaces {
		dev := strings.TrimSpace(i.Device)
		if dev == "" {
			dev = strings.TrimSpace(i.Name)
		}
		if dev != "" {
			ifaces = append(ifaces, dev)
		}
	}
	sort.Strings(ifaces)
	resp := map[string]any{
		"enabled":     true,
		"ifaces":      ifaces,
		"routes":      len(st.routing.Routes),
		"policyRules": len(st.routing.Rules),
		"lastError":   m.getLastError(),
	}
	b, _ := json.Marshal(resp)
	return b
}
