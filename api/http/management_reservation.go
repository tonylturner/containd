// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

// ManagementGuardHealth is supplied by management startup, not config or API
// input. It reads the guard in the engine's network namespace.
type ManagementGuardHealth func(context.Context) (netcfg.ManagementHealth, error)

// ManagementListenerFaults exposes boot-only optional listener failures.
type ManagementListenerFaults func() []string

func managementReservationHandler(store config.Store, health ManagementGuardHealth, engine EngineClient, listeners ManagementListenerFaults) gin.HandlerFunc {
	return func(c *gin.Context) {
		r := config.ReservationForStore(store)
		if r == nil {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		sources := make([]string, 0, len(r.Sources))
		for _, source := range r.Sources {
			sources = append(sources, source.String())
		}
		guard := netcfg.ManagementHealth{Error: "engine guard unavailable"}
		if health != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), engineHealthTimeout)
			observed, err := health(ctx)
			cancel()
			if err != nil {
				guard.Error = err.Error()
			} else {
				guard = observed
			}
		}
		fault := ""
		if faults, ok := store.(interface {
			ManagementRollbackFault(context.Context) (string, error)
		}); ok {
			var err error
			fault, err = faults.ManagementRollbackFault(c.Request.Context())
			if err != nil {
				internalError(c, err)
				return
			}
		}
		bootFault, err := config.ManagementBootFaultForStore(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		recovery := ""
		if bootFault != "" {
			ctx, cancel := context.WithTimeout(c.Request.Context(), engineHealthTimeout)
			recovery = managementRecoveryStatus(ctx, store, engine)
			cancel()
		}
		var listenerFaults []string
		if listeners != nil {
			listenerFaults = listeners()
		}
		c.JSON(http.StatusOK, gin.H{
			"bootFault": bootFault,
			"recovery":  recovery, "listenerFaults": listenerFaults,
			"active": true, "device": r.Device, "local": r.Local.String(),
			"sources": sources, "port": r.Port, "guard": guard, "rollbackFault": fault,
		})
	}
}
