// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

var errCandidateRejected = errors.New("candidate edit rejected")

// Configuration responses are classified at successful persistence boundaries,
// not by URL: preview and no-op requests can share a route with staged edits.
const configResponseHeader = "X-Containd-Config"

func configChangeResponse(c *gin.Context, state string) {
	c.Header(configResponseHeader, state)
}

func committedConfigResponse(c *gin.Context, status string) {
	configChangeResponse(c, "committed")
	c.JSON(http.StatusOK, gin.H{"status": status})
}

func replaceCandidate(c *gin.Context, ctx context.Context, store config.Store, cfg *config.Config) bool {
	if err := store.SaveCandidate(ctx, cfg); err != nil {
		apiError(c, http.StatusBadRequest, err.Error())
		return false
	}
	configChangeResponse(c, "staged")
	return true
}

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
	configChangeResponse(c, "staged")
	auditLog(c, audit.Record{
		Action: "config.stage",
		Target: c.Request.URL.Path,
		Detail: "candidate",
	})
	return saved, true
}
