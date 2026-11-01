// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/common/evidence"
)

func readEvidence(providers ...any) evidence.Status {
	status := evidence.Status{Audit: evidence.AuditStatus{State: evidence.StateUnknown}, Forwarding: []evidence.ForwardStatus{}}
	for _, provider := range providers {
		if reporter, ok := provider.(evidence.AuditReporter); ok {
			status.Audit = reporter.AuditStatus()
		}
		if reporter, ok := provider.(evidence.ForwardReporter); ok {
			if forwarding := reporter.ForwardStatus(); forwarding != nil {
				status.Forwarding = forwarding
			}
		}
	}
	return status
}

func evidenceStatusHandler(providers ...any) gin.HandlerFunc {
	return func(c *gin.Context) { c.JSON(http.StatusOK, readEvidence(providers...)) }
}

// Unknown is worse than recovered: lack of observation cannot certify recovery.
// A known failure outranks unknown so missing producers never hide degradation.
func evidenceHealth(status evidence.Status) evidence.State {
	rank := func(s evidence.State) int {
		switch s {
		case evidence.StateOK:
			return 0
		case evidence.StateRecovered:
			return 1
		case evidence.StateDegraded:
			return 3
		default:
			return 2
		}
	}
	state := status.Audit.State
	if rank(state) == 2 {
		state = evidence.StateUnknown
	}
	for _, forward := range status.Forwarding {
		if rank(forward.State) > rank(state) {
			state = forward.State
			if rank(state) == 2 {
				state = evidence.StateUnknown
			}
		}
	}
	return state
}
