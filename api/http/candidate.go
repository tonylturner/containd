// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

var errCandidateRejected = errors.New("candidate edit rejected")

// stageCandidate owns the complete read/modify/validate/write boundary. A
// rejected edit has already sent its domain-specific HTTP error and is never
// persisted. Responses are sent only after the store accepts the entire edit.
func stageCandidate(c *gin.Context, store config.Store, edit func(*config.Config) bool) (*config.Config, bool) {
	var saved *config.Config
	err := store.MutateCandidate(c.Request.Context(), func(cfg *config.Config) error {
		if !edit(cfg) {
			return errCandidateRejected
		}
		saved = cfg
		return nil
	})
	if err != nil {
		if !errors.Is(err, errCandidateRejected) {
			apiError(c, http.StatusBadRequest, err.Error())
		}
		return nil, false
	}
	auditLog(c, audit.Record{
		Action: "config.stage",
		Target: c.Request.URL.Path,
		Detail: "candidate",
	})
	return saved, true
}
