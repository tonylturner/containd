// SPDX-License-Identifier: Apache-2.0
package netcfg

import (
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

const (
	// ManagementTable cannot be addressed by the student's 1..252 routing tables.
	ManagementTable uint32 = 104000
	// ManagementRouteProtocol is separate from normal containd routes (98).
	ManagementRouteProtocol = 99
)

type ManagementFault struct {
	Time      time.Time `json:"time"`
	Interface string    `json:"interface,omitempty"`
	Address   string    `json:"address,omitempty"`
	Service   string    `json:"service,omitempty"`
	Reason    string    `json:"reason"`
}
type ManagementHealth struct {
	Active    bool             `json:"active"`
	Device    string           `json:"device,omitempty"`
	Local     string           `json:"local,omitempty"`
	Port      uint16           `json:"port,omitempty"`
	Sources   []string         `json:"sources,omitempty"`
	Error     string           `json:"error,omitempty"`
	Faults    uint64           `json:"faults"`
	LastFault *ManagementFault `json:"lastFault,omitempty"`
}

// ManagementGuard owns subscription, pin and local-table repairs. Fault history
// is sticky and visible even after repair. Close waits for its worker to stop.
type ManagementGuard struct {
	reservation *mgmtpath.Reservation
	reconcileMu sync.Mutex
	mu          sync.Mutex
	health      ManagementHealth
	notify      func(ManagementFault)
	cancel      func()
	done        chan struct{}
}

func (g *ManagementGuard) Status() ManagementHealth {
	if g == nil {
		return ManagementHealth{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.health
	if !s.Active && s.Error == "" {
		s.Error = "management netlink subscription unavailable"
	}
	s.Sources = append([]string(nil), s.Sources...)
	if s.LastFault != nil {
		f := *s.LastFault
		s.LastFault = &f
	}
	return s
}
func (g *ManagementGuard) fault(f ManagementFault) {
	f.Time = time.Now().UTC()
	g.mu.Lock()
	g.health.Faults++
	g.health.LastFault = &f
	g.mu.Unlock()
	if g.notify != nil {
		g.notify(f)
	}
}
func (g *ManagementGuard) setError(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.health.Error = ""
	if err != nil {
		g.health.Error = err.Error()
	}
}
func (g *ManagementGuard) setActive(active bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.health.Active = active
}
func (g *ManagementGuard) Close() {
	if g != nil {
		g.cancel()
		<-g.done
		g.setActive(false)
	}
}
