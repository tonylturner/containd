// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

// boundManagement is the management listeners this boot serves.
type boundManagement struct {
	// cfg is the runtime configuration whose listener settings are bound.
	cfg       *config.Config
	listener  mgmtListenerConfig
	servers   []*http.Server
	listeners []net.Listener
	// event is the boot fault event of a listener fallback, nil without one.
	event *dpevents.Event
}

// bindManagement binds the management listeners of cfg, with build
// creating the servers of a listener configuration. Without a reservation,
// stored listener settings that cannot be bound must not stop management:
// the restart loop that follows would lock it out. Management then binds
// the appliance default listeners instead and enters management recovery
// with the bind failure as its boot fault, joined to any stored conflict.
// A failure of the defaults themselves, or of listeners the environment
// sets, stays fatal. With a reservation the reserved path decides (see
// reservationSafeBootListeners).
func bindManagement(logger *zap.SugaredLogger, stores mgmtStores, cfg *config.Config, r *mgmtpath.Reservation, listener mgmtListenerConfig, build func(mgmtListenerConfig) ([]*http.Server, []net.Listener, error)) (boundManagement, error) {
	servers, listeners, err := build(listener)
	if err == nil {
		return boundManagement{cfg: cfg, listener: listener, servers: servers, listeners: listeners}, nil
	}
	if r != nil {
		return boundManagement{}, err
	}
	fallback := httpapi.WithApplianceListeners(cfg, nil)
	fallbackListener, ferr := resolveMgmtListenerConfig(logger, fallback, nil)
	if ferr != nil || sameBinds(listener, fallbackListener) {
		return boundManagement{}, err
	}
	bindErr := fmt.Errorf("management listener: %w", err)
	logger.Errorw("stored management listeners cannot be bound; serving the default listeners", "error", err)
	if servers, listeners, ferr = build(fallbackListener); ferr != nil {
		return boundManagement{}, errors.Join(bindErr, fmt.Errorf("default management listeners: %w", ferr))
	}
	event, perr := persistBootFault(logger, stores, errors.Join(bootConflict(cfg, nil), bindErr), nil)
	if perr != nil {
		for _, ln := range listeners {
			_ = ln.Close()
		}
		return boundManagement{}, perr
	}
	return boundManagement{cfg: fallback, listener: fallbackListener, servers: servers, listeners: listeners, event: event}, nil
}

// sameBinds reports whether a and b bind the same sockets, so that
// retrying one after the other failed cannot help.
func sameBinds(a, b mgmtListenerConfig) bool {
	return a.enableHTTP == b.enableHTTP && a.enableHTTPS == b.enableHTTPS &&
		(!a.enableHTTP || a.httpAddr == b.httpAddr && a.httpLoopbackAddr == b.httpLoopbackAddr) &&
		(!a.enableHTTPS || a.httpsAddr == b.httpsAddr && a.httpsLoopbackAddr == b.httpsLoopbackAddr)
}
