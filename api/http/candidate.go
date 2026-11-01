// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
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
	revision, err := store.SaveCandidate(ctx, expectedConfigRevision(c), cfg)
	if err != nil {
		if revisionMismatchResponse(c, err) {
			return false
		}
		apiError(c, http.StatusBadRequest, err.Error())
		return false
	}
	configRevisionResponse(c, revision)
	configChangeResponse(c, "staged")
	return true
}

// stageCandidate owns the complete read/modify/validate/write boundary. A
// rejected edit has already sent its domain-specific HTTP error and is never
// persisted. Responses are sent only after the store accepts the entire edit.
func stageCandidate(c *gin.Context, store config.Store, edit func(*config.Config) bool) (*config.Config, bool) {
	return stageCandidateWith(c, store.MutateCandidate, edit)
}

// stageCandidateIDS is reserved for edits or responses that need the bank.
func stageCandidateIDS(c *gin.Context, store config.Store, edit func(*config.Config) bool) (*config.Config, bool) {
	bankStore, ok := store.(config.IDSCandidateStore)
	if !ok {
		internalError(c, errors.New("store does not support IDS candidate edits"))
		return nil, false
	}
	return stageCandidateWith(c, bankStore.MutateCandidateIDS, edit)
}

func stageCandidateWith(c *gin.Context, mutate func(context.Context, config.Revision, func(*config.Config) error) (config.Revision, error), edit func(*config.Config) bool) (*config.Config, bool) {
	var saved *config.Config
	revision, err := mutate(c.Request.Context(), expectedConfigRevision(c), func(cfg *config.Config) error {
		if !edit(cfg) {
			return errCandidateRejected
		}
		saved = cfg
		return nil
	})
	if err != nil {
		if revisionMismatchResponse(c, err) {
			return nil, false
		}
		if !errors.Is(err, errCandidateRejected) {
			apiError(c, http.StatusBadRequest, err.Error())
		}
		return nil, false
	}
	configRevisionResponse(c, revision)
	configChangeResponse(c, "staged")
	return saved, true
}

// Service discovery runs outside mutation callbacks because validators can read
// the store. It needs only settings, never the potentially large IDS bank.
func loadCandidateDocument(ctx context.Context, store config.Store) (*config.Config, error) {
	reader, ok := store.(interface {
		LoadCandidateDocument(context.Context) (*config.Config, error)
	})
	if !ok {
		return nil, errors.New("store does not support bank-free document reads")
	}
	return reader.LoadCandidateDocument(ctx)
}
