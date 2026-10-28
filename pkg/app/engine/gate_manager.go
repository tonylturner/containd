// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/httpgate"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The gate manager runs the scanning gate beside the data plane: it keeps
// the transparent listeners the policy steers selected connections to,
// dials their upstream legs with the client's address, feeds the gate its
// settings, and tells the policy whether new selected connections may be
// delivered. It runs while the data plane enforces, whatever the selection
// holds, so that gated connections outlive a selection change.

// gateAdmitter switches the policy's admission of new gated connections.
type gateAdmitter interface {
	SetGateAdmit(ctx context.Context, state enforce.GateAdmitState) error
}

const (
	gateAdmitTimeout    = 10 * time.Second
	gateShutdownTimeout = 5 * time.Second
	gateDialAttempts    = 4
)

type gateManager struct {
	logger   *zap.SugaredLogger
	scanner  avscan.Scanner
	admit    gateAdmitter // nil leaves the policy's switch untouched
	events   *events.Store
	ports    [2]uint16 // plain, masquerading
	registry *gateRegistry

	// The socket, routing and sysctl operations are fields so tests can run
	// the manager with plain loopback sockets on any platform.
	listen        func(ctx context.Context, network, address string) (net.Listener, error)
	dial          func(ctx context.Context, network string, local netip.Addr, mark uint32, server netip.AddrPort) (*net.TCPConn, error)
	originalDst   func(*net.TCPConn) (netip.AddrPort, error)
	effectiveDst  func(*net.TCPConn) netip.AddrPort
	ensureRouting func(context.Context) error
	removeRouting func(context.Context) error
	fwmarkAccept  func() (bool, error)

	mu         sync.Mutex
	server     *httpgate.Server // nil while stopped
	cancel     context.CancelFunc
	done       chan struct{}
	listeners  []*gateListener
	gate       rules.GateSelection
	av         config.AVConfig
	settings   httpgate.Settings
	routingOK  bool
	routingErr string
	warning    string

	// admitMu serialises the policy switch; applied is the state the policy
	// holds when appliedKnown.
	admitMu      sync.Mutex
	applied      enforce.GateAdmitState
	appliedKnown bool
	admitErr     string
}

func newGateManager(logger *zap.SugaredLogger, scanner avscan.Scanner, admit gateAdmitter, store *events.Store, plainPort, masqPort uint16) *gateManager {
	g := &gateManager{
		logger:        logger,
		scanner:       scanner,
		admit:         admit,
		events:        store,
		ports:         [2]uint16{plainPort, masqPort},
		registry:      newGateRegistry(),
		listen:        gateTransparentListen,
		dial:          gateTransparentDial,
		originalDst:   gateOriginalDst,
		effectiveDst:  func(c *net.TCPConn) netip.AddrPort { return gateAddrPort(c.LocalAddr()) },
		ensureRouting: netcfg.EnsureGateRouting,
		removeRouting: netcfg.RemoveGateRouting,
		fwmarkAccept:  gateFwmarkAccept,
	}
	g.settings = gateSettings(g.gate, g.av)
	return g
}

// setEnforcing starts the gate when the data plane enforces and stops it
// when it does not.
func (g *gateManager) setEnforcing(on bool) {
	if g == nil {
		return
	}
	if on {
		g.start()
		return
	}
	g.stop()
}

// close stops the gate at process end.
func (g *gateManager) close() {
	g.setEnforcing(false)
}

func (g *gateManager) start() {
	g.mu.Lock()
	if g.server != nil {
		g.mu.Unlock()
		return
	}
	srv := &httpgate.Server{
		Scanner:     g.scanner,
		OriginalDst: g.originalDstHook,
		Dial:        g.dialHook,
		OnEvent:     g.eventHook,
	}
	if err := srv.Update(g.settings); err != nil {
		// gateSettings always yields valid settings; this is a programming error.
		g.mu.Unlock()
		panic("gate settings: " + err.Error())
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.server, g.cancel, g.done = srv, cancel, make(chan struct{})
	g.routingOK, g.routingErr, g.warning = false, "", ""
	g.appliedKnown = false
	g.listeners = g.newListeners()
	listeners := g.listeners
	done := g.done
	g.mu.Unlock()
	g.syncAdmit()
	go g.run(ctx, srv, listeners, done)
}

func (g *gateManager) stop() {
	g.mu.Lock()
	srv, cancel, done := g.server, g.cancel, g.done
	g.server, g.cancel, g.done = nil, nil, nil
	g.mu.Unlock()
	if srv == nil {
		return
	}
	cancel()
	ctx, cancelShutdown := context.WithTimeout(context.Background(), gateShutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(ctx); err != nil {
		g.logger.Warnf("gate shutdown: %v", err)
	}
	<-done
	if err := g.removeRouting(ctx); err != nil && !gateUnsupported(err) {
		g.logger.Warnf("gate routing removal: %v", err)
	}
	g.mu.Lock()
	g.listeners = nil
	g.routingOK, g.routingErr = false, ""
	g.appliedKnown = false
	g.mu.Unlock()
	g.logger.Infof("scanning gate stopped")
}

// applySnapshot takes the selection of an applied rule snapshot.
func (g *gateManager) applySnapshot(gate rules.GateSelection) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.gate = gate
	g.mu.Unlock()
	g.refreshSettings()
}

// applyAV takes the applied AV configuration.
func (g *gateManager) applyAV(av config.AVConfig) {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.av = av
	g.mu.Unlock()
	g.refreshSettings()
}

func (g *gateManager) refreshSettings() {
	g.mu.Lock()
	g.settings = gateSettings(g.gate, g.av)
	srv := g.server
	if srv != nil {
		if err := srv.Update(g.settings); err != nil {
			g.logger.Errorf("gate settings: %v", err)
		}
	}
	g.mu.Unlock()
	if srv != nil {
		g.syncAdmit()
	}
}

// CloseMatching resets both legs of every gated connection req matches.
func (g *gateManager) CloseMatching(req engine.GateCloseRequest) int {
	if g == nil {
		return 0
	}
	n := g.registry.closeMatching(req)
	if n > 0 {
		g.logger.Infof("scanning gate reset %d connection(s) for %s", n, gateCloseRequestString(req))
	}
	return n
}

func gateCloseRequestString(req engine.GateCloseRequest) string {
	if req.Host.IsValid() {
		return "host " + req.Host.String()
	}
	return fmt.Sprintf("%s:%d -> %s:%d", req.Src, req.SrcPort, req.Dst, req.DstPort)
}

// originalDstHook gives the gate the effective destination: the address the
// listener accepted the connection for, which is the destination after DNAT.
func (g *gateManager) originalDstHook(c net.Conn) (netip.AddrPort, error) {
	gc, ok := c.(*gateConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("gate: %T was not accepted by a gate listener", c)
	}
	if !gc.entry.effective.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("gate: no effective destination for %s", gc.entry.client)
	}
	return gc.entry.effective, nil
}

// dialHook opens the upstream leg from the client's address, marked as the
// gate's own and, for a connection accepted on the masquerading listener,
// as one to masquerade. The kernel picks the local port; the client's own
// port is refused, since the upstream leg would then carry the client
// leg's tuple.
func (g *gateManager) dialHook(ctx context.Context, client, server netip.AddrPort) (net.Conn, error) {
	entry := g.registry.lookup(client, server)
	mark := enforce.GateUpstreamSockMark
	if entry != nil && entry.masq {
		mark |= enforce.GateMasqSockMark
	}
	network := "tcp4"
	if server.Addr().Is6() {
		network = "tcp6"
	}
	for attempt := 1; attempt <= gateDialAttempts; attempt++ {
		c, err := g.dial(ctx, network, client.Addr(), mark, server)
		if err != nil {
			return nil, err
		}
		local := gateAddrPort(c.LocalAddr())
		if local.Port() == client.Port() {
			c.Close()
			continue
		}
		if entry == nil {
			return c, nil
		}
		entry.setUpstream(c, local)
		return &gateUpstreamConn{TCPConn: c, entry: entry}, nil
	}
	return nil, fmt.Errorf("gate dial %s: the kernel kept choosing the client's port %d", server, client.Port())
}

// eventHook records a gate event with the pre-DNAT destination it knows.
func (g *gateManager) eventHook(ev httpgate.Event) {
	var original netip.AddrPort
	if entry := g.registry.lookup(ev.Client, ev.Server); entry != nil {
		original = entry.original
	}
	if g.events != nil {
		g.events.Append(gateEvent(ev, original))
	}
	if ev.Verdict == avscan.Infected {
		g.logger.Warnf("scanning gate blocked %s %s -> %s: %s (%s)", ev.Direction, ev.Client, ev.Server, ev.Signature, ev.Backend)
	}
}

// desiredAdmitLocked is the admission the policy should hold: delivery
// when every listener and the routing are up, otherwise the fail policy's
// treatment of a selected connection. Callers hold mu.
func (g *gateManager) desiredAdmitLocked() enforce.GateAdmitState {
	if g.server != nil && g.routingOK && g.listenersUpLocked() {
		return enforce.GateAdmitOpen
	}
	if g.settings.FailPolicy == avscan.FailOpen {
		return enforce.GateAdmitPass
	}
	return enforce.GateAdmitRefuse
}

// syncAdmit brings the policy's switch to the desired admission when that
// changed. It serialises switches so a later decision never loses to an
// earlier one still in flight.
func (g *gateManager) syncAdmit() {
	g.admitMu.Lock()
	defer g.admitMu.Unlock()
	g.mu.Lock()
	if g.server == nil {
		g.mu.Unlock()
		return
	}
	want := g.desiredAdmitLocked()
	if g.appliedKnown && g.applied == want {
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	var err error
	if g.admit != nil {
		ctx, cancel := context.WithTimeout(context.Background(), gateAdmitTimeout)
		err = g.admit.SetGateAdmit(ctx, want)
		cancel()
	}
	g.mu.Lock()
	g.applied, g.appliedKnown = want, err == nil
	g.admitErr = ""
	if err != nil {
		g.admitErr = err.Error()
	}
	st := g.statusLocked()
	g.mu.Unlock()
	if err != nil {
		g.logger.Errorf("scanning gate admission %s: %v", want, err)
	} else {
		g.logger.Infof("scanning gate admission %s (state %s)", want, st.State)
	}
	if g.events != nil {
		attrs := map[string]any{"state": st.State, "admit": want.String(), "fail_policy": st.FailPolicy}
		if err != nil {
			attrs["error"] = err.Error()
		}
		g.events.Append(events.Event{Proto: "av", Kind: gateEventState, Timestamp: time.Now().UTC(), Attributes: attrs})
	}
}

// gateStatus is the gate's part of the AV status.
type gateStatus struct {
	// State is off while the data plane does not enforce; refuse or pass
	// while a listener or the routing is down, by fail policy; pending
	// while the gate runs but the scanner is not ready; else open.
	State        string               `json:"state"`
	Enabled      bool                 `json:"enabled"`
	FailPolicy   string               `json:"fail_policy"`
	Admit        string               `json:"admit"`
	AdmitError   string               `json:"admit_error,omitempty"`
	Listeners    []gateListenerStatus `json:"listeners"`
	Scanner      gateScannerStatus    `json:"scanner"`
	Connections  int                  `json:"connections"`
	RoutingError string               `json:"routing_error,omitempty"`
	Warning      string               `json:"warning,omitempty"`
}

type gateListenerStatus struct {
	Address     string `json:"address"`
	Masquerade  bool   `json:"masquerade"`
	Up          bool   `json:"up"`
	Error       string `json:"error,omitempty"`
	Unavailable bool   `json:"unavailable,omitempty"`
}

type gateScannerStatus struct {
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

func (g *gateManager) status() gateStatus {
	if g == nil {
		return gateStatus{State: "off", Admit: enforce.GateAdmitRefuse.String(), Listeners: []gateListenerStatus{}}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.statusLocked()
}

func (g *gateManager) statusLocked() gateStatus {
	st := gateStatus{
		Enabled:      g.gate.Enabled,
		FailPolicy:   string(g.settings.FailPolicy),
		Admit:        g.applied.String(),
		AdmitError:   g.admitErr,
		Listeners:    []gateListenerStatus{},
		Connections:  g.registry.count(),
		RoutingError: g.routingErr,
		Warning:      g.warning,
	}
	st.Scanner.Ready, st.Scanner.Error = g.scanner.Ready()
	for _, l := range g.listeners {
		st.Listeners = append(st.Listeners, l.status())
	}
	switch {
	case g.server == nil:
		st.State = "off"
	case !g.routingOK || !g.listenersUpLocked():
		st.State = g.desiredAdmitLocked().String()
	case !st.Scanner.Ready:
		st.State = "pending"
	default:
		st.State = "open"
	}
	return st
}

// gateFollower is the config handler's data plane: it reconfigures the
// engine, then runs or stops the gate with the engine's enforcement.
type gateFollower struct {
	*engine.Engine
	gate *gateManager
}

func (f gateFollower) Reconfigure(fresh *engine.Engine) error {
	if err := f.Engine.Reconfigure(fresh); err != nil {
		return err
	}
	f.gate.setEnforcing(f.Engine.Updater() != nil)
	return nil
}
